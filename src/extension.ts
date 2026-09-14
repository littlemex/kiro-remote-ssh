import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import { Log, LogLevel } from './log';
import { ProductMetadata, ProductMetadataError, readProductMetadata } from './product';
import { HostTreeProvider } from './hosts';
import { AuthoritySession } from './session';

const AUTHORITY_PREFIX = 'ssh-remote';

/**
 * The adapter onto the proposed API, and nothing else.
 *
 * Everything below this file can be exercised without the editor, which is the
 * reason it is this thin.
 */
export function activate(context: vscode.ExtensionContext): void {
    const log = new Log('Remote - SSH');
    context.subscriptions.push({ dispose: () => log.dispose() });
    log.setLevel(readLogLevel());

    // Registered before anything that can fail, so the view and its commands exist
    // even when this build turns out not to support remote development. An empty
    // panel that explains itself beats no panel at all.
    const hosts = new HostTreeProvider();
    try {
        context.subscriptions.push(vscode.window.registerTreeDataProvider('kiroRemoteSsh.hosts', hosts));
    } catch (err) {
        // A build that does not accept the view contribution should still be able to
        // connect. Registering a provider for a view the workbench never created
        // throws, and taking activation down with it would remove the commands too.
        log.error('the host list view is unavailable in this build', err);
    }
    context.subscriptions.push(
        vscode.commands.registerCommand('kiroRemoteSsh.showLog', () => log.show()),
        vscode.commands.registerCommand('kiroRemoteSsh.refreshHosts', () => hosts.refresh()),
        vscode.commands.registerCommand('kiroRemoteSsh.connect', () => connectCommand(log)),
        vscode.commands.registerCommand('kiroRemoteSsh.connectToHost', (alias: string) => openHost(alias, log)),
        vscode.commands.registerCommand('kiroRemoteSsh.openConfig', async () => {
            const file = path.join(os.homedir(), '.ssh', 'config');
            await vscode.window.showTextDocument(vscode.Uri.file(file), { preview: false });
        }),
    );

    let product: ProductMetadata;
    try {
        product = readProductMetadata();
    } catch (err) {
        // Without this there is nothing to connect to, and saying so once is more
        // useful than failing later inside a resolve the user cannot read.
        const message = err instanceof ProductMetadataError ? err.message : String(err);
        log.error('this build cannot be used for remote development', err);
        void vscode.window.showErrorMessage(`Remote - SSH: ${message}`);
        return;
    }
    log.info(`host application reports commit ${product.commit.slice(0, 8)}, server ${product.serverApplicationName}`);

    const sessions = new Map<string, AuthoritySession>();
    context.subscriptions.push({
        dispose: () => {
            for (const session of sessions.values()) {
                session.dispose();
            }
            sessions.clear();
        },
    });

    // `registerRemoteAuthorityResolver` only exists when the proposal is enabled
    // for this extension, and the failure mode without it is that nothing happens
    // at all. Naming it is the difference between a five-minute fix and an
    // afternoon.
    const workspaceApi = vscode.workspace as unknown as {
        registerRemoteAuthorityResolver?: (prefix: string, resolver: unknown) => vscode.Disposable;
    };
    if (typeof workspaceApi.registerRemoteAuthorityResolver !== 'function') {
        const message =
            'Remote - SSH cannot register itself because the resolvers API proposal is not enabled. Add "littlemex.kiro-remote-ssh" to "enable-proposed-api" in argv.json and restart.';
        log.error(message);
        void vscode.window
            .showErrorMessage(message, 'Open argv.json')
            .then((choice) => {
                if (choice === 'Open argv.json') {
                    void vscode.commands.executeCommand('workbench.action.configureRuntimeArguments');
                }
            });
        return;
    }

    const resolver = {
        /**
         * Forwarding is part of resolving, not an extra.
         *
         * The host only installs a tunnel provider if the resolver supplies this
         * function: for a managed authority its own fallback is an empty method
         * that returns nothing. So an extension omitting `tunnelFactory` leaves
         * the remote window with no port forwarding at all, and `asExternalUri`
         * silently has nothing to offer. Any remote extension that has to send
         * the user to a URL it serves — a sign-in, most obviously — cannot work.
         */
        tunnelFactory: (
            tunnelOptions: { remoteAddress: { host: string; port: number }; localAddressPort?: number },
        ) => {
            const session = [...sessions.values()][0];
            if (!session) {
                return undefined;
            }
            return session.createTunnel(tunnelOptions);
        },
        resolve: async (authority: string, ctx: { resolveAttempt: number }) => {
            const [prefix, host] = splitAuthority(authority);
            if (prefix !== AUTHORITY_PREFIX) {
                throw new Error(`${authority} is not an ${AUTHORITY_PREFIX} authority`);
            }
            let session = sessions.get(host);
            if (!session) {
                session = new AuthoritySession(host, product, log, context.globalState);
                sessions.set(host, session);
            }
            try {
                return await session.resolve(ctx.resolveAttempt);
            } catch (err) {
                log.error(`could not resolve ${host}`, err);
                session.dispose();
                sessions.delete(host);
                throw err;
            }
        },
    };

    context.subscriptions.push(workspaceApi.registerRemoteAuthorityResolver(AUTHORITY_PREFIX, resolver));
    log.info(`registered the ${AUTHORITY_PREFIX} resolver`);

    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration('kiroRemoteSsh.logLevel')) {
                log.setLevel(readLogLevel());
            }
        }),
    );
}

export function deactivate(): void {
    // Sessions are disposed through the subscription registered in activate.
}

async function connectCommand(log: Log): Promise<void> {
    const host = await vscode.window.showInputBox({
        title: 'Connect to SSH Host',
        prompt: 'Host name, or an alias from your SSH config',
        placeHolder: 'user@host or my-alias',
        ignoreFocusOut: true,
    });
    if (!host) {
        return;
    }
    await openHost(host, log);
}

async function openHost(alias: string, log: Log): Promise<void> {
    log.info(`opening a window for ${alias}`);
    await vscode.commands.executeCommand('vscode.newWindow', {
        remoteAuthority: `${AUTHORITY_PREFIX}+${encodeAuthorityHost(alias)}`,
        reuseWindow: false,
    });
}

function splitAuthority(authority: string): [string, string] {
    const plus = authority.indexOf('+');
    if (plus < 0) {
        return [authority, ''];
    }
    return [authority.slice(0, plus), decodeAuthorityHost(authority.slice(plus + 1))];
}

/**
 * Authorities are compared as opaque strings by the editor, so the host part has
 * to survive a round trip through one. Hex keeps it inside the characters an
 * authority allows without inventing an escaping scheme.
 */
function encodeAuthorityHost(host: string): string {
    return Buffer.from(host, 'utf8').toString('hex');
}

function decodeAuthorityHost(encoded: string): string {
    if (/^[0-9a-f]+$/.test(encoded) && encoded.length % 2 === 0) {
        return Buffer.from(encoded, 'hex').toString('utf8');
    }
    return encoded;
}

function readLogLevel(): LogLevel {
    const value = vscode.workspace.getConfiguration('kiroRemoteSsh').get<string>('logLevel', 'info');
    return value === 'debug' || value === 'trace' ? value : 'info';
}
