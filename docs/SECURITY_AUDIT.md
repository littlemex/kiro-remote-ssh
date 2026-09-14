# Audit of existing Remote-SSH options for Kiro

This records what was measured about the community extensions that can be
installed into Kiro from Open VSX, because those measurements are the reason this
project exists and the reason its design is shaped the way it is. It is written
as findings and reproduction steps. Judgements about the projects or their
authors are out of scope.

Audited against Kiro 1.0.437, commit `5349479558af37fecbfcdb58c199ee59d86d4dd3`,
on macOS, in September 2026. Versions are the ones published on Open VSX at that
time. Everything below is static analysis of published artifacts; no exploit was
attempted against any host.

## Subjects

| Extension | Version | Downloads at time of audit |
|---|---|---|
| `jeanp413.open-remote-ssh` | 0.3.1 | 805,028 |
| `saurav-z.vsc-ssh-extension` | 1.1.0 | 16,352 |
| `quanticware.vscodium-ssh-explorer` | 0.2.10 | 4,622 |
| `aergic.zygos-kiro` | 0.4.4 | 10,018 |

## Findings in `jeanp413.open-remote-ssh` 0.3.1

### 1. Server host keys are not verified

The extension constructs an `ssh2` client in two places. Neither passes
`hostVerifier` or `hostHash`. The vendored `ssh2` treats an absent verifier as
unconditional acceptance; its own debug string for this path reads
`Host accepted by default (no verification)`.

The string `known_hosts` does not occur anywhere in the published bundle
(`lib/extension.js`, 599,605 characters). The seven occurrences of
`fingerprint` all concern the *client's own* identity keys, used to choose which
key to offer.

The repository contains `src/ssh/hostfile.ts` (42 lines), which implements
reading and appending hashed `known_hosts` entries. No module imports it, which
is why the bundler omits it from the published artifact.

Consequence: a connection is established to whatever key the peer presents, with
no comparison against a recorded key, no first-use confirmation, and no
fingerprint shown.

Reproduce:

```
grep -c known_hosts lib/extension.js
grep -rn 'hostVerifier\|checkNewHostInHostkeys\|addHostToHostFile' src/
```

### 2. The vendored SSH library predates the CVE-2023-48795 mitigation

`package.json` declares `"ssh2": "git+https://github.com/jeanp413/ssh2#master"`
— an unpinned branch of a fork. That fork's last commit is dated 2023-09-30 and
it is 29 commits behind `mscdex/ssh2`. The first missing upstream commit is
`97b223f8`, *lib: add strict key exchange mode support*, which is the strict key
exchange mitigation for CVE-2023-48795. Also missing are `be9165bf`
(*client: fix implicit key hashing during rekey*) and `cd353df0`
(*keyParser: fix equals()*).

In the published bundle, `kex-strict-c-v00@openssh.com` occurs zero times, while
`chacha20-poly1305` occurs five times and `etm@openssh.com` six times.

The fork's own four commits were reviewed. Two are a `.gitignore` and a lockfile.
`bdc906b9` fixes agent authentication when the server reports partial success.
`a169f627` moves `convertToMpint` into `utils.js` and applies it to the `r` and
`s` values in `sigSSHToASN1`; upstream did not normalise them, which made some
valid ECDSA signatures fail to parse. Neither weakens a check.

Reproduce:

```
gh api repos/jeanp413/ssh2/compare/jeanp413:master...mscdex:master --jq '.total_commits, [.commits[].commit.message]'
grep -c 'kex-strict-c-v00@openssh.com' lib/extension.js
```

### 3. Local forwards bind every interface

Two servers are created for forwarding — the SOCKS server and the port-forward
server — and both call `listen` with a port and no bind address, so Node binds
all interfaces. `remote.SSH.enableDynamicForwarding` defaults to `true`, so the
SOCKS server, which has no authentication, is started by default.

The same bundle's own helpers `findRandomPort` and `findFreePort` pass
`'127.0.0.1'` explicitly, so the omission is confined to these two call sites.

### 4. The downloaded server archive is not checked for integrity

`src/scripts/server-setup.sh` (292 lines) downloads the server tarball and
extracts it. It contains no digest, signature or checksum step; `tar -xO` is used
to detect a truncated archive. Integrity therefore rests on TLS to the endpoint.

### 5. Lower-severity observations

- With `remote.SSH.serverValidation` set to `force`, the setup script rewrites
  the remote `product.json` commit field with `sed`.
- The composed `ProxyCommand` is written to the trace log, which discloses
  anything embedded in it.
- `remote.SSH.serverValidation` set to `skip` passes
  `--disable-client-side-validation`, a flag that does not appear in Kiro's
  remote server, so that setting prevents the server from starting. This is an
  availability issue rather than a security one.

### Practices that were checked and found sound

Passwords and passphrases are not persisted: `keytar`, `SecretStorage` and
`secrets.store` do not occur in the bundle, and prompt results are held in
memory. `ProxyCommand` is executed with `spawn` and an argument vector, parsed by
a quote-aware parser, so there is no shell interpolation. The remote server is
started bound to `127.0.0.1`, its connection token comes from
`crypto.randomUUID` and is written to a file created `0600`, and
`--telemetry-level off` is passed.

## Findings in `saurav-z.vsc-ssh-extension` 1.1.0

The extension declares an `ssh-remote` resolver, but cannot complete a
connection on Kiro through its normal installation flow, for two independent
reasons.

Its `ServerManager` builds the download URL as
`https://update.code.visualstudio.com/commit:<commit>/server-<platform>/stable`,
taking `<commit>` from the running application's `package.json`. For a Kiro
commit that URL returns HTTP 404; as a control, the same URL for the Microsoft
VS Code stable commit `645f29cc3176500b4b5762ba887cf2a7f0ffdf2c` returns HTTP
200 and 216,833,164 bytes. It installs into `~/.code-server` and looks for a
binary named `code-server`.

Separately, it requires the `resolvers`, `tunnels` and `terminalDataWriteEvent`
proposed APIs. Without the extension id in `enable-proposed-api` in
`~/.kiro/argv.json` it logs a warning and the resolver is never registered.

## `quanticware.vscodium-ssh-explorer` 0.2.10

Browses a remote file tree over SFTP. Its own description states that there is no
agent to install on the server. The window is not a remote window, so the
integrated terminal and any agent continue to run locally. This is the
extension's stated purpose, not a defect; it is recorded here because its status
bar entry is easily mistaken for a remote connection indicator.

## `aergic.zygos-kiro` 0.4.4

Reads the host application's `product.json` to build the correct
`kiro-reh-${os}-${arch}` URL, verifies the archive against SHA-256 before
extraction, and shells out to the system `ssh` binary rather than vendoring an
SSH implementation. On the three points above where the most-used option was
found wanting, this one takes the approach this project also takes. It was first
published on 2026-09-04 and was not audited in the depth applied to
`jeanp413.open-remote-ssh`.

## What the audit changed in this project's design

- SSH is delegated to the system `ssh` binary, so host key policy and key
  exchange policy are OpenSSH's and are updated with it (findings 1 and 2).
- No listener is created on a non-loopback address, and the primary channel
  creates no listener at all (finding 3).
- Archive digests are recorded on first use and enforced afterwards, and are
  checked before extraction rather than after (finding 4).
- The remote `product.json` is never rewritten, because making a mismatch
  disappear defeats the check that notices it (finding 5).
- Composed command lines are never logged (finding 5).

## Disclosure status

Not yet reported upstream. Findings 1 to 4 are being prepared for
`jeanp413/open-remote-ssh`, and finding 1 has a small fix available in that
project's own unused `src/ssh/hostfile.ts`. This section will record the report
once it is filed; until then this document is the only place they are written
down, which is stated here so that nobody infers a coordinated disclosure that
has not happened.
