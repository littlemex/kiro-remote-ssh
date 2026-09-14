# Design

## What this is

A Remote-SSH extension for [Kiro](https://kiro.dev): open a folder on a remote
Linux host so that the editor, the integrated terminal, workspace extensions and
the Kiro agent all execute on that host, over a plain SSH connection.

Kiro ships a remote extension host (REH) but no extension that connects to it.
The installed `product.json` declares `serverApplicationName`,
`serverDataFolderName` and a `serverDownloadUrlTemplate` for
`kiro-reh-${os}-${arch}`, and the Linux tarballs for the installed commit are
served. What is missing is the client half: something that resolves the
`ssh-remote` authority, puts the REH on the host, and connects the workbench.

## Why not use an existing extension

The community options were audited first; the audit is in
[SECURITY_AUDIT.md](SECURITY_AUDIT.md). The finding that drives this design is
that the most widely used option reimplements the SSH client in JavaScript, and
that reimplementation performs no server host key verification and vendors an SSH
library that predates the strict key exchange mitigation for CVE-2023-48795.
Those are not isolated bugs. They are what owning an SSH implementation costs.

So the central decision is to not own one.

## Central decision: delegate SSH to OpenSSH

Every SSH operation shells out to the system `ssh` binary. The extension never
speaks the SSH protocol, never parses a private key, and ships no cryptographic
code.

What delegation actually buys needs stating precisely, because the obvious
phrasing overclaims. Delegation does not make host key verification or strict
key exchange *guaranteed*. It transfers **policy and maintenance
responsibility** to OpenSSH and to the user's own configuration: the behaviour
becomes whatever their `ssh` does when they type it themselves, and it improves
when they update OpenSSH rather than when this extension is updated.

That transfer is only worth something if the thing being delegated to is known.
So the extension must establish what it is talking to:

- The executable is resolved from an explicit `remote.SSH.path` setting when
  present, otherwise from `PATH`.
- `ssh -V` is run once per session. The implementation and version are recorded
  in the log and surfaced in diagnostics.
- Non-OpenSSH implementations are rejected with one sentence naming what was
  found. There is no best-effort path: a client whose option semantics are
  unknown cannot be reasoned about.
- OpenSSH 8.4 is the minimum, because the askpass bridge below depends on
  `SSH_ASKPASS_REQUIRE`. Older versions are rejected, not warned about.

The cost of delegation is a hard dependency on `ssh` and on the user's SSH
configuration being correct, and misconfiguration surfaces as the same error
they would get in their own terminal. A host that is only reachable through a
bastion, or through an `aws ssm start-session` `ProxyCommand`, needs no
extension-side support at all.

## One transport per authority

This is the constraint that shapes everything else, and it is a correctness
requirement rather than a performance one.

A `Host` alias does not name a machine. It names a way of connecting. Two
separate `ssh` invocations to the same alias can land on different machines: a
`ProxyCommand` that picks a backend, a load-balanced bastion, `Match exec` whose
result depends on time or environment, DNS returning several addresses, an
ephemeral VM behind a gateway. If the REH is started by one invocation and the
forward is created by another, the forward can point at a host where nothing is
listening — and the failure is intermittent, which is worse than consistent.

Therefore: **one persistent SSH transport per resolved authority, and everything
multiplexed onto it.** Implemented with OpenSSH connection multiplexing — an
extension-owned `ControlPath`, `ControlMaster` established once, and every
subsequent operation (bootstrap, the extension host channel, user port forwards)
issued through `-S <path>` against that master. The master is closed when the
authority is disposed.

This also fixes the authentication count. Without it, a user on password, OTP or
a FIDO2 token authenticates once per `ssh` invocation, several times per window.

`ControlPath` length limits and control socket behaviour on Windows clients are
unverified and are a spike item, not an assumption.

## Interactive authentication

An `ssh` spawned from a GUI process has no TTY. Left alone, password
authentication, key passphrases, keyboard-interactive and MFA, FIDO2 PIN entry,
and the first-connection host key confirmation all fail — not with a prompt the
user can answer, but with an error. "The extension never prompts for a
passphrase" is a feature gap dressed as a virtue.

The extension therefore ships an **askpass bridge**: a small helper set as
`SSH_ASKPASS`, with `SSH_ASKPASS_REQUIRE=force` so it is used without a
`DISPLAY`, that forwards the prompt over a local IPC channel to the extension
and returns the answer the user types into an input box. The helper handles
prompt text only. It does not see private keys, and it does not implement any
part of SSH.

Host key confirmation is routed through the same bridge and is **never
auto-accepted**. The fingerprint OpenSSH reports is shown verbatim and the user
answers. A host key that conflicts with `known_hosts` is a refusal, not a
prompt.

## Which SSH options are ours

The user's configuration is inherited on purpose, but not all of it can be,
because some of it can create listeners or run commands that this extension is
otherwise promising not to create or run. `LocalForward 0.0.0.0:…`,
`DynamicForward`, `RemoteForward`, `RemoteCommand`, `LocalCommand` with
`PermitLocalCommand`, `RequestTTY` and `SessionType` all change what an
invocation does.

So each kind of invocation has an explicit option set, and the options this
extension depends on are passed on the command line, where they win over the
config file. Host selection, authentication, and reachability (`HostName`,
`User`, `Port`, `IdentityFile`, `ProxyCommand`, `ProxyJump`, `Match`, `Include`)
are inherited. Forwarding and remote-command directives are overridden per
invocation: the bootstrap and the extension host channel pass
`-o ClearAllForwardings=yes` and an explicit `SessionType`, so a user's
forwarding directives cannot attach themselves to the extension's own
connections.

The consequence for the security posture below is that a guarantee about
*this extension's* listeners is achievable, and a guarantee about every listener
on the machine is not. The posture says the former.

Effective per-host settings are never re-derived by parsing config ourselves.
`ssh -G <host>` asks OpenSSH. Config files are parsed for exactly one purpose:
enumerating `Host` entries for the picker.

## Shape

Six responsibilities. The first is an adapter and the rest are testable without
Kiro.

| Component | Owns |
|---|---|
| `Resolver` | The proposed-API surface. Registers the `ssh-remote` resolver and translates. Deliberately thin. |
| `AuthoritySession` | One authority's state machine and lifecycle: resolve, re-resolve, dispose, cancellation. |
| `OpenSSHTransport` | The `ssh` executable: capability detection, the master connection, `exec`, `-W`, `-L`, the askpass bridge, stderr classification. |
| `ArtifactProvisioner` | Acquiring the REH tarball, digest handling, archive inspection, atomic install. |
| `RehManager` | Starting the server, liveness probing, the connection token, install locking, reuse and GC. |
| `ProductMetadata` | Reading commit, URL template and server names out of the local `product.json`. |

`Resolver` and `AuthoritySession` are separate because re-resolution after a
network drop is a state transition, not a fresh resolve, and the supervision of
that belongs somewhere nameable.

## The extension host channel

Kiro's extension host implements `ManagedResolvedAuthority` (verified in
`out/vs/workbench/api/node/extensionHostProcess.js`: a managed authority routes
through `setFactory(…, makeConnection)` instead of a `host:port`). So the
primary channel can be a byte stream rather than a socket:

```
ManagedResolvedAuthority.makeConnection()
  └─ ssh -S <control-path> -T -W 127.0.0.1:<reh-port> <host>
```

with the child's stdin and stdout bridged to the connection. No local listener
exists for the primary channel at all, which removes local port collisions, the
window between choosing a free port and binding it, and the question of which
other local processes could reach that port.

This is a **spike before commitment**, not an assumption. What has to be
established on the machine is backpressure behaviour, reconnection, and close
semantics of Kiro's managed connections, plus correct child stdio lifecycle.
If the spike fails, the fallback is `-L` with an explicit `127.0.0.1` bind,
`ExitOnForwardFailure=yes`, and a retry on collision.

Note that a fully stdio-only design is not available: the REH listens on TCP, so
even in the managed case the remote side is reached by `-W` to remote loopback.

## Forwarding is not optional

Port forwarding looks like a convenience next to the channel above, and it is
not. The host installs a tunnel provider only if the resolver supplies a
`tunnelFactory`; for a managed authority its own fallback is a method with an
empty body that returns nothing. A resolver that omits it therefore leaves the
remote window with no forwarding at all, and `asExternalUri` — the API a remote
extension uses to hand the user a URL their own browser can open — has nothing to
offer.

The consequence is not a missing feature but a broken one somewhere else
entirely: a remote extension that has to authenticate serves its sign-in
callback on the remote loopback and asks `asExternalUri` to make it reachable.
Without forwarding it never becomes reachable, so that extension can never be
signed in on that host. This was found by connecting successfully and then
watching the remote agent fail with a missing token, which is not a symptom
anybody would trace back to a tunnel provider by reading code.

Forwards are created with `-O forward` against the connection that already
exists, rather than by starting another `ssh`. Reusing the established
connection is what keeps the single-transport guarantee: a second invocation
could authenticate again and, worse, land on a different machine. Every forward
binds `127.0.0.1` explicitly and points at the host's own loopback; forwarding to
any other address on the remote would turn this machine into a route into the
remote network, which is not what a port forward for an editor is for.

Dynamic (SOCKS) forwarding is not implemented.

## Authentication on the remote

The host asks you to sign in once per host, and this extension does not carry your
sign-in across for you. That is a deliberate stop rather than an omission, and the
reasons are worth keeping because they were expensive to find.

The editor offers a way to hand a local session to the remote extension host,
`authenticationSessionForInitializingExtensions`. It cannot be used from here:
resolving an authority happens **before** extensions activate, so at the only moment
the field could be filled there is no authentication provider to ask. Waiting for one
is a deadlock, and it was one — the editor sat on "invoking final resolve()" until the
wait was abandoned. Measured again with a freshly refreshed local token, so this is
ordering and not expiry.

That leaves putting a credential where the remote reads one, and a working
implementation of that was built and then removed. Two measurements decided it.

The first was that the guarantee it advertised could not be kept. Deleting the file
when the authority is disposed depends on code of ours running at the end, and on
SIGKILL, a crash, a closed lid or a power cut none runs — the credential simply
stayed on the host, which a real termination confirmed. Rebuilding it so the kernel
enforced the disappearance did work: the credential lived in anonymous memory held by
a helper on the host and was published as a symlink into that process's descriptor
table, a SIGALRM enforced a silence deadline, and `timeout` put a ceiling on the
session. Every termination path revoked it, including SIGKILL, and nothing was ever
written to a filesystem.

The second measurement is why it is gone anyway: **the reader refuses a symlink at
that path.** Its log says so plainly — `Security: symbolic link detected at token
storage path` — and it is right to. So the only shape that satisfied the lifetime
requirement is the one shape the consumer will not accept, and the shapes the consumer
accepts are the ones whose lifetime cannot be guaranteed.

Three routes remain, none of them free, and none taken yet:

- **A real file, removed on the way out.** Accepted by the reader; the lifetime
  guarantee is lost, so it would have to be described as "a credential copied to the
  host for up to its expiry" rather than as session-scoped. The client registration
  and refresh token would stay on this machine regardless, because a client secret is
  valid for months.
- **`extensionHostEnv` pointing the remote extension host's `HOME` at tmpfs.** A real
  file that does not survive a reboot, which is a genuine improvement — but it moves
  `HOME` for every extension on that host, and the consequences of that have not been
  explored.
- **Nothing, which is what ships.** One sign-in per host, in the remote window, using
  the forwarding this extension does provide.

Also worth recording, because it looks like a bug later: an extension that refreshes a
credential in the background refreshes the copy on the side it runs on. With the agent
running remotely, the copy on the client is no longer kept alive by anything.

## Not built

- Windows and macOS remote hosts: no REH is published for them.
- SOCKS / dynamic forwarding: it was the source of an all-interfaces listener in
  the audited implementation, and nothing in this flow needs it.
- An in-JS SSH client, an agent implementation, key parsing, a passphrase cache.
- Rewriting the remote `product.json` to force a commit match. Making a mismatch
  disappear defeats the check.
- A bundled `ssh` binary.
- Carrying your sign-in to the host. See above: the only mechanism whose lifetime
  could be guaranteed is rejected by the consumer, and the ones it accepts cannot be
  bounded. Signing in once per host is the supported answer.
- Windows *clients* are out of scope for the first release. Connection
  multiplexing and askpass both differ there, and pretending otherwise would put
  an untested branch through the security-critical path.


## Who enforces what

Every lifetime in this extension names the component that enforces it, and only three
kinds of enforcer are admissible: the kernel, an expiry, or a process independent of
the one being bounded. **A row whose enforcer is this extension's own cleanup code
fails review**, because on the terminations that matter — SIGKILL, a crash, a closed
lid, a power cut — that code does not run. This rule exists because a guarantee was
written into this document, shipped, and then broken by exactly that mistake.

| Thing with a lifetime | Enforcer | How a termination reaches it |
|---|---|---|
| The local listener that carries forwarded connections | Kernel | The listening descriptor is held by this process, so the kernel closes it when the process ends. Measured: twelve listeners became zero on SIGKILL. |
| The connection to the remote extension host | — | No listener exists for it; it is a byte stream over `ssh -W`. Nothing to outlive anything. |
| The shared SSH connection and its control socket | Kernel, then expiry | Its remote end reads a pipe only this process writes to, so end-of-input ends it; and it exits on its own after silence, which a host that never notices a vanished client would otherwise take over two hours to do. |
| The remote server | Expiry | Started with `--enable-remote-auto-shutdown`; it deliberately outlives a disconnect so a reconnection is cheap. |
| A credential on the host | — | None is sent. See "Authentication on the remote". |

## Verification

Function, failure, concurrency, and the posture — each checked on a machine.

Function

1. First connect to a clean Linux host installs and starts the REH.
2. A new integrated terminal reports the remote hostname.
3. The Kiro agent, asked to run a command, runs it on the host.
4. Reconnecting reuses the running server rather than reinstalling.
5. A host reachable only through a `ProxyCommand` connects.
6. Extensions install into the remote extension host from Open VSX.
7. A host with no egress connects via local fetch and upload.
8. A remote extension that needs a browser can be signed in, because
   `asExternalUri` returns a URL that resolves to a forwarded local port.

Failure and environment

9. A password-only host connects, through the askpass bridge.
10. An unknown host shows the fingerprint and waits; a host whose key conflicts
    with `known_hosts` is refused and not silently accepted.
11. A host whose login shell is `fish` and whose `.bashrc` and MOTD write to
    stdout still bootstraps, because the report is delimited.
12. A musl host, a macOS host, and a host without `tar` each fail with the one
    sentence that names the reason.
13. Network is cut mid-session and restored; the session re-resolves and unsaved
    buffers survive.
14. A local authentication provider that never answers does not prevent the
    connection.

Concurrency

15. Two windows connecting to the same host for the first time do not race; one
    installs and the other waits.
16. After Kiro updates, a new window installs the new commit and the window still
    on the old commit keeps working.

Posture

17. Nothing this extension started listens on a non-loopback address during a
    session, including with `LocalForward 0.0.0.0:...` present in the user's
    config for that host, and including while a forward is active.
18. `ps` on the remote does not show the token; the token file is `0600`.
19. The log contains neither the token nor any composed command line.
20. An archive whose bytes differ from the recorded digest for that
    `(commit, arch)` is rejected **before extraction**. An archive for a
    different commit is rejected before execution. An archive that keeps the
    expected commit and has no recorded digest is **not** detected — this is
    asserted as a known limit, not as a pass.
21. An archive containing an entry with `..`, an absolute path, or a symlink
    pointing outside the staging directory is rejected.

### Verified so far

On a throwaway Ubuntu 24.04 host, x64, glibc 2.39, with OpenSSH 10.3 locally and
9.6 on the host:

- **1** — a clean host installed and started the server, and the report came back
  with a listening port and a token.
- **4** — a second and third connection reused the running server on the same
  port. The first attempt did not: the install lock was held on a file descriptor
  the detached server inherited, so the next connection waited on a lock held by
  the very server it meant to reuse.
- **8** — a forward was created and the local end answered, which is what makes
  `asExternalUri` able to return anything at all.
- **14** — an authentication provider that never answered did not prevent the
  connection, after it was raced against a timeout. Before that it prevented it
  completely.
- **17, 18** in part — during a live session this machine had no listening socket
  for the channel, the server was bound to the host's loopback only, the token did
  not appear in any process's arguments on the host when every `/proc/*/cmdline`
  was scanned, and the token file was `0600`.

The remote extension host started, both its management and extension host
connections were established over `ssh -W`, and the agent extension was running
on the host.

**Item 3 is not verified, and the reason is not this extension.** The mechanism it
depends on is verified: a sign-in started in the remote window completed through
the forward and wrote a credential cache on the host. What the agent then reported
is that the account has no Kiro profile assigned in its directory, which is an
entitlement held elsewhere. That is a useful result rather than a gap in the
verification — it says the path is open and the remaining obstacle is not
technical. Everything else in the list remains unverified.
