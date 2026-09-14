/**
 * The parts of the `resolvers` API proposal this extension uses.
 *
 * These are declared here rather than pulled from `vscode.proposed.resolvers.d.ts`
 * so that the build does not depend on fetching a proposal file whose version
 * happens to match the host. The shapes were read out of the host's own
 * extension host bundle, which is the only definition that matters at runtime:
 * it accepts a managed authority when `typeof makeConnection === 'function'`,
 * and it drives the returned object through `onDidReceiveMessage`, `onDidClose`,
 * `onDidEnd`, `send`, `end` and an optional `drain`.
 */

export interface Disposable {
    dispose(): void;
}

export type Event<T> = (listener: (e: T) => unknown) => Disposable;

/** What `makeConnection()` must resolve to. */
export interface ManagedMessagePassing {
    onDidReceiveMessage: Event<Uint8Array>;
    onDidClose: Event<Error | undefined>;
    onDidEnd: Event<void>;
    send(data: Uint8Array): void;
    end(): void;
    drain?(): Promise<void>;
}

/**
 * Returned from `resolve()`. The host distinguishes this from a host/port
 * authority structurally, so a plain object is sufficient and avoids depending
 * on a class being exported under the proposal.
 *
 * The token must match /^[0-9A-Za-z_\-]+$/ or the host rejects it before the
 * connection is attempted.
 */
export interface ManagedResolvedAuthority {
    makeConnection: () => Promise<ManagedMessagePassing>;
    connectionToken?: string;
    /**
     * A local sign-in for the remote extension host to start extensions with.
     *
     * Declared because the host reads it, and left unset: see the note in
     * AuthoritySession.resolve. Resolving precedes extension activation, so there
     * is no authentication provider to ask at the only moment this could be
     * filled.
     */
    authenticationSessionForInitializingExtensions?: { id: string; providerId: string };
}

export interface ResolvedAuthority {
    host: string;
    port: number;
    connectionToken?: string;
}

export interface RemoteAuthorityResolverContext {
    resolveAttempt: number;
}

export interface RemoteAuthorityResolver {
    resolve(
        authority: string,
        context: RemoteAuthorityResolverContext,
    ): Promise<ManagedResolvedAuthority | ResolvedAuthority>;
}

export const CONNECTION_TOKEN_PATTERN = /^[0-9A-Za-z_-]+$/;
