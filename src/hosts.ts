import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';

/**
 * The hosts in the user's SSH configuration, and somewhere to click.
 *
 * Config files are read for exactly one purpose: listing the `Host` entries so they
 * can be shown. Their effective settings are never re-derived here — `ssh -G` asks
 * OpenSSH, which is the only implementation whose answer is authoritative. Parsing
 * `Match` and `Include` semantics ourselves would be a slow betrayal of the decision
 * to delegate.
 *
 * `Include` is followed, because a user whose hosts live in an included file would
 * otherwise see an empty list and reasonably conclude the extension is broken.
 */
export interface SshHost {
    readonly alias: string;
    readonly source: string;
}

const MAX_INCLUDE_DEPTH = 8;

export function readHosts(configPath = path.join(os.homedir(), '.ssh', 'config')): SshHost[] {
    const seen = new Set<string>();
    const hosts: SshHost[] = [];
    collect(configPath, hosts, seen, 0);
    return hosts.sort((a, b) => a.alias.localeCompare(b.alias));
}

function collect(file: string, into: SshHost[], seen: Set<string>, depth: number): void {
    if (depth > MAX_INCLUDE_DEPTH || seen.has(file)) {
        return;
    }
    seen.add(file);
    let text: string;
    try {
        text = fs.readFileSync(file, 'utf8');
    } catch {
        return;
    }
    for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) {
            continue;
        }
        const [keyword, ...rest] = line.split(/\s+/);
        const key = keyword.toLowerCase();
        if (key === 'include') {
            for (const pattern of rest) {
                const resolved = pattern.startsWith('~')
                    ? path.join(os.homedir(), pattern.slice(1))
                    : path.isAbsolute(pattern)
                      ? pattern
                      : path.join(path.dirname(file), pattern);
                // Only literal paths are followed. A glob is a matter for OpenSSH,
                // and guessing at one here would produce a list that disagrees with
                // what `ssh` actually does.
                collect(resolved, into, seen, depth + 1);
            }
            continue;
        }
        if (key !== 'host') {
            continue;
        }
        for (const alias of rest) {
            // A pattern is not something anyone can connect to, so it is not offered.
            if (alias.includes('*') || alias.includes('?') || alias === '!') {
                continue;
            }
            if (!into.some((existing) => existing.alias === alias)) {
                into.push({ alias, source: file });
            }
        }
    }
}

type Node = SshHost;

/**
 * The Remote Explorer entry.
 *
 * Without it the only way to reach this extension is the command palette, which is
 * a reasonable thing for someone who already knows the extension exists and a dead
 * end for everyone else. That was the first thing a user said about it.
 */
export class HostTreeProvider implements vscode.TreeDataProvider<Node> {
    private readonly changed = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this.changed.event;

    refresh(): void {
        this.changed.fire();
    }

    getChildren(): Node[] {
        return readHosts();
    }

    getTreeItem(host: Node): vscode.TreeItem {
        const item = new vscode.TreeItem(host.alias, vscode.TreeItemCollapsibleState.None);
        item.iconPath = new vscode.ThemeIcon('vm');
        item.description = path.basename(host.source);
        item.tooltip = `Connect to ${host.alias} (from ${host.source})`;
        item.contextValue = 'kiroRemoteSshHost';
        item.command = {
            command: 'kiroRemoteSsh.connectToHost',
            title: 'Connect',
            arguments: [host.alias],
        };
        return item;
    }
}
