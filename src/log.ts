import * as vscode from 'vscode';

export type LogLevel = 'info' | 'debug' | 'trace';

const ORDER: Record<LogLevel, number> = { info: 0, debug: 1, trace: 2 };

/**
 * A log that cannot be used to leak the two things worth leaking.
 *
 * Connection tokens and composed `ssh` command lines never reach it, and that is
 * enforced by what this class does not offer rather than by remembering to
 * redact at every call site: there is no method that takes an argv, and every
 * registered secret is replaced in any message that happens to contain it.
 */
export class Log {
    private readonly channel: vscode.OutputChannel;
    private readonly secrets = new Set<string>();
    private level: LogLevel = 'info';

    constructor(name: string) {
        this.channel = vscode.window.createOutputChannel(name);
    }

    setLevel(level: LogLevel): void {
        this.level = level;
    }

    /**
     * Register a value that must never appear in the log. Short values are
     * ignored: masking them would turn ordinary text into noise without
     * protecting anything worth protecting.
     */
    addSecret(value: string | undefined): void {
        if (value && value.length >= 16) {
            this.secrets.add(value);
        }
    }

    info(message: string): void {
        this.write('info', message);
    }

    debug(message: string): void {
        this.write('debug', message);
    }

    trace(message: string): void {
        this.write('trace', message);
    }

    error(message: string, err?: unknown): void {
        const detail = err instanceof Error ? `: ${err.message}` : err !== undefined ? `: ${String(err)}` : '';
        this.write('info', `error ${message}${detail}`);
    }

    show(): void {
        this.channel.show();
    }

    dispose(): void {
        this.channel.dispose();
    }

    private write(level: LogLevel, message: string): void {
        if (ORDER[level] > ORDER[this.level]) {
            return;
        }
        let line = message;
        for (const secret of this.secrets) {
            if (line.includes(secret)) {
                line = line.split(secret).join('<redacted>');
            }
        }
        this.channel.appendLine(`[${new Date().toISOString()}] [${level}] ${line}`);
    }
}
