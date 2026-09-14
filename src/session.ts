import { ChildProcess } from 'child_process';
import * as vscode from 'vscode';
import { ManagedMessagePassing, ManagedResolvedAuthority } from './api/managed';
import { Log } from './log';
import { ProductMetadata } from './product';
import { RehManager } from './reh/manager';
import { OpenSSHTransport } from './transport/openssh';

/**
 * One authority's lifetime.
 *
 * Re-resolution after a network drop is a transition of this object, not a fresh
 * resolve: the server on the host is still there, the token is still the one it
 * was started with, and reconnecting means opening a new channel to the same
 * loopback port rather than installing anything again.
 */
export class AuthoritySession {
    private transport: OpenSSHTransport | undefined;
    private reh: RehManager | undefined;
    private endpoint: { port: number; connectionToken: string } | undefined;
    private readonly children = new Set<ChildProcess>();
    private readonly tunnels = new Set<{ dispose: () => void }>();

    constructor(
        private readonly host: string,
        private readonly product: ProductMetadata,
        private readonly log: Log,
        private readonly state: vscode.Memento,
    ) {}

    async resolve(attempt: number): Promise<ManagedResolvedAuthority> {
        this.log.info(`resolving ${this.host} (attempt ${attempt})`);
        const config = vscode.workspace.getConfiguration('kiroRemoteSsh');
        const sshPath = config.inspect<string>('sshPath')?.globalValue ?? '';
        const timeout = config.inspect<number>('connectTimeout')?.globalValue ?? 60;

        if (!this.transport) {
            this.transport = new OpenSSHTransport(this.host, this.log, sshPath);
            this.reh = new RehManager(this.transport, this.product, this.log, this.state);
        }
        await this.transport.openMaster(timeout);
        const endpoint = await this.reh!.ensureRunning();
        this.endpoint = { port: endpoint.port, connectionToken: endpoint.connectionToken };

        // No authentication session is passed on, and it is worth saying why
        // rather than leaving the field looking forgotten.
        //
        // The host can carry a local sign-in to the remote extension host through
        // `authenticationSessionForInitializingExtensions`, and the obvious way to
        // fill it is to ask the local provider for a session here. That cannot
        // work: resolving an authority happens *before* extensions activate, so at
        // this moment no authentication provider is registered — not remotely, and
        // not locally either. Asking simply waits for a provider that appears only
        // after this function returns, which is a deadlock rather than a slow path,
        // and it was one: the editor sat on "invoking final resolve()" until the
        // wait was abandoned. Measured with a valid local token in place, so it is
        // ordering and not expiry.
        //
        // What this extension owes the problem instead is forwarding, so that a
        // sign-in started on the remote can reach the user's browser. That is
        // implemented, and the token then lives on the host and is refreshed there.
        return {
            connectionToken: endpoint.connectionToken,
            makeConnection: () => this.makeConnection(),
        };
    }

    /**
     * A forward from this machine to a port on the host.
     *
     * The editor asks for these on behalf of remote extensions, most importantly
     * for `asExternalUri`: an extension on the host that needs the user's own
     * browser to visit something it is serving has no other way to be reached.
     * A sign-in on the remote is exactly that case, so without this the remote
     * agent can never be authenticated at all.
     */
    async createTunnel(options: {
        remoteAddress: { host: string; port: number };
        localAddressPort?: number;
    }): Promise<{
        remoteAddress: { host: string; port: number };
        localAddress: { host: string; port: number };
        protocol?: string;
        onDidDispose: vscode.Event<void>;
        dispose: () => void;
    }> {
        if (!this.transport) {
            throw new Error('a tunnel was requested before the authority was resolved');
        }
        // Only the host's own loopback is forwarded. Asking for another address
        // would make this machine a route into the remote network, which is not
        // what a port forward for an editor is for.
        const forward = await this.transport.listenForRemotePort(
            options.remoteAddress.port,
            options.localAddressPort,
        );
        const onDidDispose = new vscode.EventEmitter<void>();
        let disposed = false;
        const tunnel = {
            remoteAddress: { host: '127.0.0.1', port: options.remoteAddress.port },
            localAddress: { host: '127.0.0.1', port: forward.localPort },
            onDidDispose: onDidDispose.event,
            dispose: () => {
                if (disposed) {
                    return;
                }
                disposed = true;
                forward.dispose();
                this.tunnels.delete(tunnel);
                onDidDispose.fire();
                onDidDispose.dispose();
            },
        };
        this.tunnels.add(tunnel);
        return tunnel;
    }

    /**
     * A channel to the server, as bytes rather than as a socket.
     *
     * Nothing listens locally for this. The editor asks for a connection, an
     * `ssh -W` child is opened on the shared transport, and its stdio is the
     * connection.
     */
    private async makeConnection(): Promise<ManagedMessagePassing> {
        if (!this.transport || !this.endpoint) {
            throw new Error('a connection was requested before the authority was resolved');
        }
        const child = await this.transport.connectToRemotePort(this.endpoint.port);
        this.children.add(child);

        const onMessage = new vscode.EventEmitter<Uint8Array>();
        const onClose = new vscode.EventEmitter<Error | undefined>();
        const onEnd = new vscode.EventEmitter<void>();

        let settled = false;
        const settle = (err?: Error) => {
            if (settled) {
                return;
            }
            settled = true;
            this.children.delete(child);
            if (err) {
                onClose.fire(err);
            } else {
                onEnd.fire();
            }
        };

        child.stdout?.on('data', (chunk: Buffer) => onMessage.fire(new Uint8Array(chunk)));
        // stderr carries ssh's own diagnostics, never protocol bytes, which is why
        // the two are kept apart rather than merged.
        child.stderr?.on('data', (chunk: Buffer) => {
            const text = chunk.toString().trimEnd();
            if (text) {
                this.log.debug(`channel stderr: ${text}`);
            }
        });
        child.once('error', (err) => settle(err instanceof Error ? err : new Error(String(err))));
        child.once('exit', (code, signal) => {
            if (code === 0 || code === null) {
                settle();
            } else {
                settle(new Error(`the channel to ${this.host} closed with code ${code}${signal ? ` (${signal})` : ''}`));
            }
        });

        return {
            onDidReceiveMessage: (listener) => onMessage.event(listener),
            onDidClose: (listener) => onClose.event(listener),
            onDidEnd: (listener) => onEnd.event(listener),
            send: (data: Uint8Array) => {
                child.stdin?.write(Buffer.from(data));
            },
            end: () => {
                child.stdin?.end();
            },
            drain: async () => {
                const stdin = child.stdin;
                if (!stdin || stdin.writableLength === 0) {
                    return;
                }
                // Backpressure is real here: the editor can write faster than the
                // channel drains, and ignoring it grows an unbounded buffer in
                // this process.
                await new Promise<void>((resolve) => stdin.once('drain', () => resolve()));
            },
        };
    }

    dispose(): void {
        for (const tunnel of [...this.tunnels]) {
            tunnel.dispose();
        }
        this.tunnels.clear();
        for (const child of this.children) {
            child.kill();
        }
        this.children.clear();
        // Give the reclaim a moment to reach the host before the connection is
        // torn down; a credential left behind is worse than a slow dispose.
        setTimeout(() => {
            this.transport?.dispose();
            this.transport = undefined;
        }, 1_500);
        this.endpoint = undefined;
    }
}
