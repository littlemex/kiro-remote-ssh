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
        const args = [
            '-M',
            '-S', this.controlPath,
            '-o', `ConnectTimeout=${Math.max(1, Math.round(connectTimeoutSeconds))}`,
            '-o', 'ControlPersist=no',
            '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=4',
            ...this.ownOptions(),
            '-N',
            this.host,
        ];
        this.log.debug(`opening the multiplexed connection to ${this.host}`);
        const child = this.spawnSsh(args);
        this.master = child;

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
     * Forward a local loopback port to a port on the host's loopback interface.
     *
     * This is what makes `asExternalUri` work, and without it a remote extension
     * that authenticates cannot: its sign-in callback listens on the *remote*
     * loopback and expects the editor to hand the user a URL their own browser
     * can open. With no forwarding there is no such URL, and the sign-in cannot
     * be completed on the remote at all.
     *
     * `-O forward` attaches the forward to the connection that already exists
     * rather than starting another `ssh`, so it inherits the authentication
     * already done and cannot land on a different machine.
     */
    async forwardToRemotePort(remotePort: number, requestedLocalPort?: number): Promise<{ localPort: number; dispose: () => void }> {
        await this.openMasterIfNeeded();
        const localPort = requestedLocalPort && requestedLocalPort > 0 ? requestedLocalPort : await freeLoopbackPort();
        const spec = `127.0.0.1:${localPort}:127.0.0.1:${remotePort}`;
        const { stderr, code } = await this.run(
            this.capabilities!.executable,
            ['-S', this.controlPath, '-O', 'forward', '-L', spec, this.host],
            undefined,
            30_000,
        );
        if (code !== 0) {
            throw new OpenSSHError(
                `could not forward local port ${localPort} to port ${remotePort} on ${this.host}${classify(stderr)}`,
            );
        }
        this.log.info(`forwarding 127.0.0.1:${localPort} to loopback port ${remotePort} on ${this.host}`);
        return {
            localPort,
            dispose: () => {
                void this.run(
                    this.capabilities!.executable,
                    ['-S', this.controlPath, '-O', 'cancel', '-L', spec, this.host],
                    undefined,
                    15_000,
                );
                this.log.debug(`stopped forwarding 127.0.0.1:${localPort}`);
            },
        };
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

/**
 * A free loopback port, chosen by the kernel.
 *
 * The window between closing this probe and `ssh` binding the port is real, so
 * every forward is issued with ExitOnForwardFailure: losing the race has to
 * surface as an error rather than as a forward that silently is not there.
 */
function freeLoopbackPort(): Promise<number> {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.unref();
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const address = server.address();
            const port = typeof address === 'object' && address ? address.port : 0;
            server.close(() => (port ? resolve(port) : reject(new OpenSSHError('could not find a free local port'))));
        });
    });
}
