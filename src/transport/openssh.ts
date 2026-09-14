import { spawn, ChildProcess } from 'child_process';
import * as net from 'net';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Log } from '../log';

export class OpenSSHError extends Error {}

export interface SshCapabilities {
    readonly executable: string;
    readonly banner: string;
    readonly major: number;
    readonly minor: number;
}

/**
 * How long the shared connection tolerates silence from this client.
 *
 * Comfortably longer than the heartbeat that keeps it alive, so an ordinary pause
 * does not tear down a working session, and far shorter than the two hours a host
 * would otherwise take to notice.
 */
const MASTER_SILENCE_TIMEOUT_SECONDS = 90;

/** Below this, the askpass bridge has no way to force itself into use. */
const MINIMUM_OPENSSH = { major: 8, minor: 4 };

/**
 * The one place that runs `ssh`.
 *
 * Everything for one authority goes through a single multiplexed connection, and
 * that is a correctness requirement rather than an optimisation. A `Host` alias
 * names a way of connecting, not a machine: a `ProxyCommand` that picks a
 * backend, a load-balanced bastion, `Match exec`, or DNS returning several
 * addresses can all send two separate invocations to two different hosts. A
 * server started by one and a forward created by another would then disagree
 * about which loopback they mean, intermittently.
 */
export class OpenSSHTransport {
    private capabilities: SshCapabilities | undefined;
    private master: ChildProcess | undefined;
    private readonly controlPath: string;
    private disposed = false;
    private readonly listeners = new Set<net.Server>();
    private masterHeartbeat: NodeJS.Timeout | undefined;

    constructor(
        private readonly host: string,
        private readonly log: Log,
        private readonly executableSetting: string,
    ) {
        // Control sockets live under a short private directory because the path
        // goes into a sockaddr_un, which is around 104 bytes on macOS.
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krs-'));
        fs.chmodSync(dir, 0o700);
        this.controlPath = path.join(dir, 'c');
    }

    /**
     * Establish what we are delegating to before delegating anything to it.
     *
     * Delegation only means something if the thing delegated to is known, so a
     * client whose option semantics are not OpenSSH's is refused rather than
     * used on a best-effort basis.
     */
    async detect(): Promise<SshCapabilities> {
        if (this.capabilities) {
            return this.capabilities;
        }
        const executable = this.executableSetting.trim() || 'ssh';
        const { stderr, stdout, code } = await this.run(executable, ['-V'], undefined, 15_000);
        // OpenSSH prints its version on stderr.
        const banner = (stderr + stdout).trim().split('\n')[0] ?? '';
        if (code !== 0 && !banner) {
            throw new OpenSSHError(`could not run ${executable}; a working OpenSSH client is required`);
        }
        const match = /OpenSSH_(\d+)\.(\d+)/.exec(banner);
        if (!match) {
            throw new OpenSSHError(
                `${executable} reports "${banner || 'nothing'}", which is not OpenSSH; only OpenSSH is supported because no other client's option semantics are known`,
            );
        }
        const major = Number(match[1]);
        const minor = Number(match[2]);
        if (major < MINIMUM_OPENSSH.major || (major === MINIMUM_OPENSSH.major && minor < MINIMUM_OPENSSH.minor)) {
            throw new OpenSSHError(
                `${banner} is older than OpenSSH ${MINIMUM_OPENSSH.major}.${MINIMUM_OPENSSH.minor}, which is required so that password and passphrase prompts can be shown`,
            );
        }
        this.capabilities = { executable, banner, major, minor };
        this.log.info(`using ${banner}`);
        return this.capabilities;
    }

    /**
     * Options that belong to this extension rather than to the user.
     *
     * Host selection, authentication and reachability are inherited from the
     * user's own config on purpose. Forwarding and remote-command directives are
     * not: a `LocalForward 0.0.0.0:...`, a `RemoteCommand`, or a `DynamicForward`
     * in the user's config for this host would otherwise attach itself to the
     * connections this extension opens, and the promise that this extension
     * creates no non-loopback listener would stop being true.
     */
    private ownOptions(): string[] {
        return [
            '-o', 'ClearAllForwardings=yes',
            '-o', 'PermitLocalCommand=no',
            '-o', 'RequestTTY=no',
            '-o', 'ExitOnForwardFailure=yes',
        ];
    }

    private multiplexOptions(): string[] {
        return ['-o', 'ControlMaster=no', '-S', this.controlPath];
    }

    async openMaster(connectTimeoutSeconds: number): Promise<void> {
        await this.detect();
        if (this.master) {
            return;
        }
        // The master is given a command that reads its standard input, rather than
        // `-N`, so that this process's own death ends it.
        //
        // With `-N` the master has nothing to notice: when the extension host is
        // killed the master is orphaned and keeps the connection open forever. That
        // was measured — nine of them accumulated, and the host's session count
        // climbed with them. Holding a pipe means the write end closes when we die,
        // for any reason, and `ssh` sees end-of-input locally and exits. Locally
        // matters: waiting for the *host* to notice would mean waiting for TCP
        // keepalive, which is over two hours.
        const args = [
            '-M',
            '-S', this.controlPath,
            '-o', `ConnectTimeout=${Math.max(1, Math.round(connectTimeoutSeconds))}`,
            '-o', 'ControlPersist=no',
            '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=4',
            ...this.ownOptions(),
            this.host,
            // Two independent reasons for this connection to end, neither of which
            // is code of ours running at the right moment.
            //
            // The first is end-of-input: the write end of this pipe is held only by
            // this process, so it closes when this process does, however it goes.
            // The second is silence: if nothing arrives for a while the remote side
            // exits on its own, and a remote command exiting was measured to end the
            // local `ssh` and remove its control socket. That matters because the
            // host cannot be relied on to notice a vanished client — a host with no
            // `ClientAliveInterval` falls back to TCP keepalive, which is over two
            // hours on Linux.
            //
            // `read -t` needs a shell that has it; `sh` on Debian derivatives does
            // not, so bash is named explicitly and the fallback is end-of-input
            // alone rather than a silent loss of the timer.
            `if command -v bash >/dev/null 2>&1; then exec bash -c 'while read -r -t ${MASTER_SILENCE_TIMEOUT_SECONDS} _; do :; done'; else exec cat > /dev/null; fi`,
        ];
        this.log.debug(`opening the multiplexed connection to ${this.host}`);
        const child = this.spawnSsh(args);
        this.master = child;
        // Deliberately not ended: this pipe is the master's lifeline. Closing it,
        // or dying, is what stops it.
        child.stdin?.on('error', () => undefined);
        // Written by this process, so it stops when this process stops. A helper
        // that outlived us would keep the connection alive after we were gone,
        // which is the failure this whole arrangement exists to avoid.
        this.masterHeartbeat = setInterval(() => {
            child.stdin?.write('\n');
        }, (MASTER_SILENCE_TIMEOUT_SECONDS / 3) * 1000);

        let stderr = '';
        child.stderr?.on('data', (chunk: Buffer) => {
            stderr += chunk.toString();
            this.log.trace(`master stderr: ${chunk.toString().trimEnd()}`);
        });

        const ready = new Promise<void>((resolve, reject) => {
            const deadline = setTimeout(() => {
                reject(new OpenSSHError(`connecting to ${this.host} timed out`));
            }, Math.max(5, connectTimeoutSeconds) * 1000);
            const poll = setInterval(async () => {
                if (this.disposed) {
                    return;
                }
                if (await this.masterAlive()) {
                    clearInterval(poll);
                    clearTimeout(deadline);
                    resolve();
                }
            }, 250);
            child.once('exit', (code) => {
                clearInterval(poll);
                clearTimeout(deadline);
                reject(
                    new OpenSSHError(
                        `ssh to ${this.host} exited with code ${code ?? 'unknown'}${classify(stderr)}`,
                    ),
                );
            });
        });

        await ready;
        this.log.info(`connected to ${this.host}`);
    }

    private async masterAlive(): Promise<boolean> {
        const { code } = await this.run(
            this.capabilities!.executable,
            ['-S', this.controlPath, '-O', 'check', this.host],
            undefined,
            10_000,
        );
        return code === 0;
    }

    /** Run a command on the host through the shared connection. */
    async exec(command: string, stdin?: string, timeoutMs = 900_000): Promise<{ stdout: string; stderr: string; code: number | null }> {
        await this.openMasterIfNeeded();
        return this.run(
            this.capabilities!.executable,
            [...this.multiplexOptions(), ...this.ownOptions(), this.host, command],
            stdin,
            timeoutMs,
        );
    }

    /**
     * A byte stream to a port on the host's loopback interface.
     *
     * `-W` means no local listener exists for this channel, which removes local
     * port collisions and the question of which other processes on this machine
     * could reach it.
     */
    async connectToRemotePort(port: number): Promise<ChildProcess> {
        await this.openMasterIfNeeded();
        const args = [
            ...this.multiplexOptions(),
            ...this.ownOptions(),
            '-T',
            '-W', `127.0.0.1:${port}`,
            this.host,
        ];
        this.log.debug(`opening a channel to loopback port ${port} on ${this.host}`);
        return this.spawnSsh(args);
    }

    /**
     * A local listener that carries connections to a port on the host's loopback.
     *
     * The listening socket is owned by this process, not by `ssh`, and that is the
     * whole point. Every arrangement where `ssh` listens was measured and every one
     * of them leaves the listener behind when this process is killed: with
     * `-O forward`, with `-S ... -N -L`, and with `-S ... -L` plus a remote command,
     * the listening descriptor belongs to the multiplexing master, so killing the
     * child that asked for it changes nothing. Dropping multiplexing does make the
     * listener die with its own `ssh`, but then every forward authenticates again
     * and the host accumulates sessions.
     *
     * Holding the descriptor here settles it by a different route. The kernel closes
     * it when this process ends, for any reason, so the enforcer is not `ssh`'s
     * decision to exit, not a version-dependent reading of which channels count as
     * open, and not code of ours that runs at the end. Each accepted connection is
     * carried by an `ssh -W` child over the shared connection, so authentication
     * still happens once.
     *
     * Choosing the port here rather than probing for a free one also removes a race
     * that had a nastier consequence than it looks: a probe followed by a bind in
     * another process can lose to anything that takes the port in between, and an
     * orphaned forward from an earlier session holding that number would have had a
     * new session's URLs pointing into an older host.
     */
    async listenForRemotePort(
        remotePort: number,
        requestedLocalPort?: number,
    ): Promise<{ localPort: number; dispose: () => void }> {
        await this.openMasterIfNeeded();
        const children = new Set<ChildProcess>();
        const server = net.createServer((socket) => {
            void this.connectToRemotePort(remotePort)
                .then((child) => {
                    children.add(child);
                    socket.pipe(child.stdin!);
                    child.stdout!.pipe(socket);
                    const close = () => {
                        children.delete(child);
                        child.kill();
                        socket.destroy();
                    };
                    socket.once('error', close);
                    socket.once('close', close);
                    child.once('exit', close);
                })
                .catch((err) => {
                    this.log.error(`could not carry a connection to loopback port ${remotePort}`, err);
                    socket.destroy();
                });
        });
        server.on('error', (err) => this.log.error('the local listener failed', err));

        const localPort = await new Promise<number>((resolve, reject) => {
            server.once('error', reject);
            server.listen(requestedLocalPort ?? 0, '127.0.0.1', () => {
                const address = server.address();
                if (typeof address === 'object' && address) {
                    resolve(address.port);
                } else {
                    reject(new OpenSSHError('the local listener reported no port'));
                }
            });
        });
        this.log.info(`listening on 127.0.0.1:${localPort} for loopback port ${remotePort} on ${this.host}`);
        this.listeners.add(server);

        return {
            localPort,
            dispose: () => {
                this.listeners.delete(server);
                server.close();
                for (const child of children) {
                    child.kill();
                }
                children.clear();
                this.log.debug(`stopped listening on 127.0.0.1:${localPort}`);
            },
        };
    }

    /**
     * Run a long-lived command on the host with pipes attached.
     *
     * Distinct from `exec` because the caller keeps talking to it: this is how the
     * credential lease is held open, and its stdin is the channel a credential
     * travels on so that it never appears in a command line.
     *
     * `-T` is deliberate. With a pty, a closing channel arrives as SIGHUP or EIO
     * rather than as end-of-input, and the remote side would have to guess which.
     */
    async spawnCommand(command: string): Promise<ChildProcess> {
        await this.openMasterIfNeeded();
        return this.spawnSsh([
            ...this.multiplexOptions(),
            ...this.ownOptions(),
            '-T',
            this.host,
            command,
        ]);
    }

    /**
     * A long-lived command on a connection of its own.
     *
     * Used where the caller's own death must end the remote program. On the shared
     * connection it would not: a user's `ControlPersist` can keep that connection
     * alive after we are gone, and the remote side would keep running. The cost is
     * one extra authentication, which is the right trade for a channel that carries
     * a credential.
     */
    async spawnUnmultiplexedCommand(command: string): Promise<ChildProcess> {
        await this.detect();
        return this.spawnSsh([
            '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none',
            '-o', 'BatchMode=no',
            ...this.ownOptions(),
            '-T',
            this.host,
            command,
        ]);
    }

    private async openMasterIfNeeded(): Promise<void> {
        if (!this.master || !(await this.masterAlive())) {
            this.master = undefined;
            await this.openMaster(60);
        }
    }

    private spawnSsh(args: string[]): ChildProcess {
        // The composed argv is never logged: a ProxyCommand can carry credentials.
        this.log.trace(`spawning ssh with ${args.length} arguments for ${this.host}`);
        return spawn(this.capabilities!.executable, args, {
            stdio: ['pipe', 'pipe', 'pipe'],
            env: { ...process.env },
        });
    }

    private run(
        executable: string,
        args: string[],
        stdin: string | undefined,
        timeoutMs: number,
    ): Promise<{ stdout: string; stderr: string; code: number | null }> {
        return new Promise((resolve) => {
            const child = spawn(executable, args, { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env } });
            let stdout = '';
            let stderr = '';
            const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
            child.stdout?.on('data', (c: Buffer) => (stdout += c.toString()));
            child.stderr?.on('data', (c: Buffer) => (stderr += c.toString()));
            child.once('error', () => {
                clearTimeout(timer);
                resolve({ stdout, stderr, code: null });
            });
            child.once('close', (code) => {
                clearTimeout(timer);
                resolve({ stdout, stderr, code });
            });
            if (stdin !== undefined) {
                child.stdin?.end(stdin);
            } else {
                child.stdin?.end();
            }
        });
    }

    static randomMarker(): string {
        return `KRS-${crypto.randomBytes(8).toString('hex')}`;
    }

    dispose(): void {
        this.disposed = true;
        if (this.masterHeartbeat) {
            clearInterval(this.masterHeartbeat);
            this.masterHeartbeat = undefined;
        }
        for (const server of this.listeners) {
            server.close();
        }
        this.listeners.clear();
        if (this.capabilities) {
            // Ask the master to exit rather than killing it, so it tears down its
            // own channels.
            void this.run(
                this.capabilities.executable,
                ['-S', this.controlPath, '-O', 'exit', this.host],
                undefined,
                10_000,
            );
        }
        this.master?.kill();
        this.master = undefined;
        try {
            fs.rmSync(path.dirname(this.controlPath), { recursive: true, force: true });
        } catch {
            // The directory is under the system temp dir; leaving it is harmless.
        }
    }
}

/**
 * OpenSSH's diagnostics are not localised, so matching on them is stable. The
 * point is to say which of the three things went wrong, because the remedies are
 * entirely different.
 */
function classify(stderr: string): string {
    if (/Host key verification failed/i.test(stderr)) {
        return ': the host key does not match the one recorded in known_hosts, so the connection was refused';
    }
    if (/Permission denied|Too many authentication failures/i.test(stderr)) {
        return ': authentication was refused by the host';
    }
    if (/Could not resolve hostname|Name or service not known/i.test(stderr)) {
        return ': the hostname could not be resolved';
    }
    if (/Connection (refused|timed out)|No route to host/i.test(stderr)) {
        return ': the host could not be reached';
    }
    const firstLine = stderr.trim().split('\n').find((l) => l.trim().length > 0);
    return firstLine ? `: ${firstLine}` : '';
}

