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

User-requested port forwards need a local listener by definition and use `-L`
with an explicit `127.0.0.1` bind. Dynamic (SOCKS) forwarding is not
implemented.

## Acquiring the server

Two acquisition paths, because many hosts cannot reach the vendor endpoint:

1. **Remote fetch.** The host downloads the tarball itself. Default when the
   host has egress.
2. **Local fetch and upload.** The client downloads and streams the archive to
   the host over the transport. Required for hosts without egress, and it has a
   second benefit: the client can compute the digest itself.

The bootstrap script is delivered on stdin to `ssh … sh`, never as a quoted
argument, and its report is delimited by a per-invocation random marker so that
a noisy `.bashrc`, an MOTD, or a non-POSIX login shell cannot be mistaken for
the report. The script assumes nothing about `PATH` or locale, sets its own
`umask`, and uses absolute paths.

Prerequisites are checked first and each failure is one sentence: a Linux host
(no macOS REH is published), glibc (the REH is not a musl build, so Alpine is
unsupported), `tar`, and `curl` or `wget` for path 1.

## Integrity, stated honestly

This is where the first draft of this design was wrong, so it is spelled out.

**Asserting that the extracted `product.json` reports the expected commit is not
an integrity check.** An attacker who can substitute the archive can also write
the expected commit into it. That assertion detects URL construction mistakes,
vendor mis-publication, and an archive for the wrong commit landing in the wrong
directory. It does not detect a malicious build.

What is actually done:

- **Digest is verified before extraction**, never after, whenever a digest is
  known. Extraction is the dangerous step and must not be reached by an archive
  that is already known to be wrong.
- **Trust on first use, recorded automatically.** The first time a given
  `(commit, arch)` archive is obtained, its SHA-256 is recorded in
  application-scoped extension state. Every later acquisition of that same
  `(commit, arch)` — including on a different host — must match, or the
  connection is refused. This catches a targeted substitution aimed at one host,
  which a manual-only pin never would because nobody sets one.
- **A manual pin overrides the recorded value**, for users who obtain a digest
  out of band.
- **Pins and the download URL template are read from application scope only.**
  Never from workspace settings and never from the remote's settings. A
  repository must not be able to relax or redirect this.
- **Extraction is inspected and staged.** Entries with absolute paths, `..`
  components, symlinks or hardlinks pointing outside the staging directory, or
  device nodes are rejected. Extraction goes to an empty staging directory and
  the result is moved into `bin/<commit>/` by rename, so a partial install never
  becomes a live one.
- The commit assertion is still performed, before the server is executed,
  because it catches the honest mistakes above cheaply.

The residual limit: Kiro publishes no digest or signature for the REH, so the
very first acquisition of a new commit trusts TLS to the vendor endpoint. Asking
the vendor to publish digests is the only general fix and is tracked as an
upstream request.

## Idempotency

"Idempotent" is not a property until the key and the liveness test are defined.

- **The install key is `(commit, arch)`.** Installs live in
  `~/.kiro-server/bin/<commit>/`, matching the layout VS Code servers use, so
  several commits coexist. This is required: after Kiro updates, existing
  windows keep using the old server while new ones use the new one.
- **The remote install is locked.** The whole bootstrap runs under `flock` on a
  per-commit lock file, falling back to a `mkdir` lock, so two windows or two
  client machines connecting for the first time cannot interleave
  check/download/extract/start. Locally, resolution is serialised per authority.
- **Liveness is not a PID check.** A server is reused only when the recorded PID
  exists, *is* a `kiro-server` for that commit, *is* listening on the recorded
  port, and its token file is readable. If any of those fails the state is
  stale: it is cleaned up and the server is started fresh. A bare PID check
  misfires on PID reuse.
- **The token is reused, not regenerated.** The REH's reconnection protocol
  requires the same token, so a reused server means reading back the stored
  token. Generating a new one on every resolve breaks reuse.
- **The server is detached** with `setsid` so that a host configured with
  systemd `KillUserProcesses=yes` does not kill it when the bootstrap session
  ends. Where it is killed anyway, that is detected and reported as itself.
- **Old commits are collected.** Installs other than the newest two that have no
  running server are removed.

## Security posture

Constraints on the implementation, not aspirations.

- The extension creates no listener on a non-loopback address. Every `-L` it
  issues carries an explicit `127.0.0.1`, and its own connections pass
  `ClearAllForwardings=yes` so user forwarding directives cannot attach to them.
  This is a statement about this extension's listeners, not about every listener
  the user's own config may create.
- No `-A`. Agent forwarding happens only if the user's own SSH config asks for
  it, where they already express such decisions.
- The connection token is 32 bytes from a CSPRNG, written to a file created
  `0600`, and passed to the REH by path, so it never appears in the host's
  process list.
- The REH binds `127.0.0.1` on the remote and is reached only through the
  transport.
- Host keys are never auto-accepted, and a `known_hosts` conflict is a refusal.
- Logs record the host alias and the kind of operation, never the composed
  command line, because a `ProxyCommand` can contain credentials — and never the
  token.

## Not built

- Windows and macOS remote hosts: no REH is published for them.
- SOCKS / dynamic forwarding: it was the source of an all-interfaces listener in
  the audited implementation, and nothing in this flow needs it.
- An in-JS SSH client, an agent implementation, key parsing, a passphrase cache.
- Rewriting the remote `product.json` to force a commit match. Making a mismatch
  disappear defeats the check.
- A bundled `ssh` binary.
- Windows *clients* are out of scope for the first release. Connection
  multiplexing and askpass both differ there, and pretending otherwise would put
  an untested branch through the security-critical path.

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

Failure and environment

8. A password-only host connects, through the askpass bridge.
9. An unknown host shows the fingerprint and waits; a host whose key conflicts
   with `known_hosts` is refused and not silently accepted.
10. A host whose login shell is `fish` and whose `.bashrc` and MOTD write to
    stdout still bootstraps, because the report is delimited.
11. A musl host, a macOS host, and a host without `tar` each fail with the one
    sentence that names the reason.
12. Network is cut mid-session and restored; the session re-resolves and
    unsaved buffers survive.

Concurrency

13. Two windows connecting to the same host for the first time do not race; one
    installs and the other waits.
14. After Kiro updates, a new window installs the new commit and the window
    still on the old commit keeps working.

Posture

15. Nothing this extension started listens on a non-loopback address during a
    session, including with `LocalForward 0.0.0.0:…` present in the user's config
    for that host.
16. `ps` on the remote does not show the token; the token file is `0600`.
17. The log contains neither the token nor any composed command line.
18. An archive whose bytes differ from the recorded digest for that
    `(commit, arch)` is rejected **before extraction**. An archive for a
    different commit is rejected before execution. An archive that keeps the
    expected commit and has no recorded digest is **not** detected — this is
    asserted as a known limit, not as a pass.
19. An archive containing an entry with `..`, an absolute path, or a symlink
    pointing outside the staging directory is rejected.
