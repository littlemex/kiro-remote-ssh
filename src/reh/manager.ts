import * as vscode from 'vscode';
import { Log } from '../log';
import { ProductMetadata, serverDownloadUrl } from '../product';
import { OpenSSHTransport } from '../transport/openssh';
// The script has to travel inside the bundle: it is delivered to the host on
// stdin, so it cannot be read from a path that only exists on this machine.
import bootstrapScript from './bootstrap.sh';

export class RehError extends Error {}

export interface RehEndpoint {
    /** Port on the host's loopback interface. */
    readonly port: number;
    readonly connectionToken: string;
    readonly reused: boolean;
    readonly logFile: string;
}

const DIGEST_STATE_KEY = 'serverDigests';

/**
 * Puts a server on the host and reports where it is listening.
 *
 * The report is delimited by a per-invocation random marker because the host's
 * stdout is not ours: an MOTD, a shell profile that prints something, or a login
 * shell that is not POSIX will all write to it. Scanning for lines that happen
 * to look like a report would make those hosts fail in a way that reads as our
 * bug.
 */
export class RehManager {
    constructor(
        private readonly transport: OpenSSHTransport,
        private readonly product: ProductMetadata,
        private readonly log: Log,
        private readonly state: vscode.Memento,
    ) {}

    async ensureRunning(): Promise<RehEndpoint> {
        const marker = OpenSSHTransport.randomMarker();
        const digest = this.expectedDigest();
        const script = this.render(marker, digest);

        this.log.info(`asking ${this.product.serverApplicationName} for commit ${short(this.product.commit)} to start`);
        const { stdout, stderr, code } = await this.transport.exec('sh', script);

        const report = extractReport(stdout, marker);
        if (!report) {
            const detail = firstMeaningfulLine(stderr) ?? firstMeaningfulLine(stdout);
            throw new RehError(
                `the host did not return a bootstrap report${detail ? `: ${detail}` : ` (ssh exited with ${code ?? 'no code'})`}`,
            );
        }
        if (report.get('exitCode') !== '0') {
            throw new RehError(firstMeaningfulLine(stderr) ?? 'the bootstrap failed on the host without saying why');
        }

        const port = Number(report.get('listeningOn'));
        const connectionToken = report.get('connectionToken') ?? '';
        if (!Number.isInteger(port) || port <= 0) {
            throw new RehError('the bootstrap reported no listening port');
        }
        // The host rejects a token outside this character set before it tries to
        // connect, so catching it here names the real problem instead.
        if (!/^[0-9A-Za-z_-]+$/.test(connectionToken)) {
            throw new RehError('the bootstrap reported a connection token the editor will not accept');
        }
        this.log.addSecret(connectionToken);

        const reused = report.get('reusedServer') === 'true';
        this.log.info(
            reused
                ? `reusing the server already running on loopback port ${port}`
                : `the server started on loopback port ${port}`,
        );

        return { port, connectionToken, reused, logFile: report.get('logFile') ?? '' };
    }

    /**
     * A pin from settings wins; otherwise the digest recorded the first time this
     * commit was seen. Recording it automatically is the point: a manual pin
     * protects only the users who set one, and almost nobody does, whereas a
     * recorded digest catches a substitution aimed at one host later.
     */
    private expectedDigest(): string {
        const pinned = vscode.workspace
            .getConfiguration('kiroRemoteSsh')
            .inspect<Record<string, string>>('serverDigests')?.globalValue;
        const fromSetting = pinned?.[this.product.commit];
        if (fromSetting) {
            return fromSetting.trim().toLowerCase();
        }
        const recorded = this.state.get<Record<string, string>>(DIGEST_STATE_KEY, {});
        return (recorded[this.product.commit] ?? '').trim().toLowerCase();
    }

    /** Record the digest a host computed, so later acquisitions must match it. */
    async recordDigest(sha256: string): Promise<void> {
        const recorded = { ...this.state.get<Record<string, string>>(DIGEST_STATE_KEY, {}) };
        if (recorded[this.product.commit] === sha256) {
            return;
        }
        recorded[this.product.commit] = sha256;
        await this.state.update(DIGEST_STATE_KEY, recorded);
        this.log.info(`recorded the server digest for commit ${short(this.product.commit)}`);
    }

    private render(marker: string, expectedSha256: string): string {
        const substitutions: Record<string, string> = {
            MARKER: marker,
            COMMIT: this.product.commit,
            DOWNLOAD_URL: serverDownloadUrl(this.product, 'linux'),
            SERVER_APP_NAME: this.product.serverApplicationName,
            SERVER_DATA_FOLDER_NAME: this.product.serverDataFolderName,
            EXPECTED_SHA256: expectedSha256,
            ARCHIVE_ON_STDIN: 'false',
        };
        let script = bootstrapScript as unknown as string;
        for (const [name, value] of Object.entries(substitutions)) {
            script = script.split(`%%${name}%%`).join(value);
        }
        // A placeholder left behind would be interpreted as a literal by the
        // shell, which fails somewhere far away from the cause.
        const leftover = /%%[A-Z_]+%%/.exec(script.replace(/^#.*$/gm, ''));
        if (leftover) {
            throw new RehError(`the bootstrap script still contains the placeholder ${leftover[0]}`);
        }
        return script;
    }
}

function extractReport(stdout: string, marker: string): Map<string, string> | undefined {
    const begin = stdout.indexOf(`${marker} begin`);
    const end = stdout.indexOf(`${marker} end`);
    if (begin < 0 || end < begin) {
        return undefined;
    }
    const body = stdout.slice(begin + `${marker} begin`.length, end);
    const fields = new Map<string, string>();
    for (const line of body.split('\n')) {
        const eq = line.indexOf('=');
        if (eq > 0) {
            fields.set(line.slice(0, eq).trim(), line.slice(eq + 1).trim());
        }
    }
    return fields;
}

function firstMeaningfulLine(text: string): string | undefined {
    for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (!line) {
            continue;
        }
        // The script prefixes its own diagnostics so they can be told apart from
        // whatever else the host's login shell decided to say.
        if (line.startsWith('error: ')) {
            return line.slice('error: '.length);
        }
    }
    for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (line && !line.startsWith('Warning: Permanently added')) {
            return line;
        }
    }
    return undefined;
}

function short(commit: string): string {
    return commit.slice(0, 8);
}
