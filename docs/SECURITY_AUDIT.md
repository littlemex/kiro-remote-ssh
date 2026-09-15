# Audit of existing Remote-SSH options for Kiro

This records what was measured about the community extensions that can be
installed into Kiro from Open VSX, because those measurements are the reason this
project exists and the reason its design is shaped the way it is. It is written as
findings and reproduction steps.

**Conflict of interest.** This is written by the author of a competing project, and
it is cited in that project's design document as the justification for its shape.
Read it with that in mind. Nothing here is a judgement about the projects or the
people who write them, and every claim is meant to be checkable against the
artifacts named below rather than taken on this author's word.

## Provenance

Audited against Kiro 1.0.437, commit `5349479558af37fecbfcdb58c199ee59d86d4dd3`,
on macOS 26.6.1, in September 2026. Versions are the ones published on Open VSX at
that time.

For `jeanp413.open-remote-ssh` 0.3.1, two artifacts were read and both are
identified here so a reader can confirm they have the same bytes:

| Artifact | SHA-256 |
|---|---|
| `open-remote-ssh.vsix` (197,426 bytes, from Open VSX) | `c6f16b225ab86925f2bd9e8cc5ba31e614978ccfa120f1509bdf6e99e5bef13f` |
| `extension/lib/extension.js` inside it (599,605 characters) | `09fbd6057a14692da46743da1eb43d6af9fd4e4bac0dd1ab434b7e436073b4e5` |
| source tarball, tag `v0.3.1`, from codeload | `744dd01ef8885e3252d98e7eca2e50cf83f56a86b6651bd8e94a324376509a53` |

Both declare version `0.3.1`. Source line numbers below refer to the `v0.3.1`
tag. Note that reading both does not prove the published bundle was produced from
that source; where a claim rests on one and not the other, this is said.

Findings 1 to 4 are static analysis. Three things were executed and are marked as
such: an HTTP request for the archive size in the `saurav-z` section, a local
`net.createServer` call to establish what Node binds by default, and one run of
Kiro's own remote server to test whether it accepts a flag. No exploit was
attempted, and nothing was executed against a machine belonging to anyone else.

Occurrence counts below were produced with `grep -o pattern file | wc -l`. The
bundle is minified onto a single line, so `grep -c` reports at most 1 and is not
the right tool; an earlier revision of this document printed occurrence counts
next to `grep -c` commands that cannot produce them.

## Subjects

| Extension | Version |
|---|---|
| `jeanp413.open-remote-ssh` | 0.3.1 |
| `saurav-z.vsc-ssh-extension` | 1.1.0 |
| `quanticware.vscodium-ssh-explorer` | 0.2.10 |

The first was read in more depth than the other two. It was the most installed
of them at the time, so it was the one whose behaviour mattered most to the
question this project started from; the asymmetry is a property of how the reading
was prioritised, not a statement that the others were found better or worse.

## Findings in `jeanp413.open-remote-ssh` 0.3.1

### 1. The server's host key is not verified

An `ssh2` client is constructed once, at `src/ssh/sshConnection.ts:238`, and
connected at `src/ssh/sshConnection.ts:262` with `.connect(this.config)`. That
config is assembled at `src/ssh/sshConnection.ts:72` and extended at
`src/ssh/sshConnection.ts:215`, and neither `hostVerifier` nor `hostHash` is ever
placed in it: across the whole of `src/`, those two identifiers occur only inside
`src/ssh/hostfile.ts`, which nothing imports.

That file is 42 lines and implements reading and appending hashed `known_hosts`
entries. Its absence from the published bundle is consistent with nothing
importing it.

The vendored `ssh2` treats an absent verifier as acceptance. Its own debug string
for that branch is in the shipped bundle verbatim:
`Host accepted by default (no verification)`.

One number here is easy to misread. `hostVerifier` occurs 8 times in the bundle,
which looks at first like a contradiction. All 8 are inside the vendored library —
its machinery for *supporting* a verifier, including the branch above — and none
is a call site supplying one. The claim is about the extension's own code, not
about whether the library has the feature.

`known_hosts` occurs 0 times in the bundle. On its own that is weak evidence,
since a path can be assembled from parts or delegated elsewhere; it is recorded as
support for the call-site finding, not as the finding itself.

Consequence: the connection does not authenticate the identity of the SSH server,
so it offers no protection against an attacker positioned on the network path.
There is no comparison against a recorded key, no first-use confirmation, and no
fingerprint shown.

Reproduce:

```
grep -rn 'hostVerifier|hostHash' src/            # only src/ssh/hostfile.ts
grep -rn 'new Client\(' src/                     # one site
grep -rn hostfile src/ --include='*.ts'          # nothing imports it
grep -o known_hosts extension/lib/extension.js | wc -l
grep -o 'Host accepted by default' extension/lib/extension.js | wc -l
```

### 2. The vendored SSH library predates the strict key exchange mitigation

This does not add severity on top of finding 1 and is recorded separately because
it has a different fix. CVE-2023-48795 (Terrapin) requires an attacker on the
network path, and finding 1 already means such an attacker is not resisted. Read
the two together rather than as two independent exposures.

`package.json` declares `"ssh2": "git+https://github.com/jeanp413/ssh2#master"` —
an unpinned branch of a fork, which is itself the durable part of this finding: what
a given install resolves to depends on when it resolved. Compared in September
2026, that branch's last commit was dated 2023-09-30 and it was 29 commits behind
`mscdex/ssh2`. Both endpoints of that comparison move, so the count is a
measurement with a date on it, not a property of the release. The first missing
upstream commit was `97b223f8`, *lib: add strict key exchange mode support*, the
strict key exchange mitigation for CVE-2023-48795. Also missing were `be9165bf`
(*client: fix implicit key hashing during rekey*) and `cd353df0`
(*keyParser: fix equals()*).

In the published bundle, `kex-strict-c-v00@openssh.com` occurs 0 times, while
`chacha20-poly1305` occurs 5 times and `etm@openssh.com` 6 times. That shows the
affected constructions are implemented and the mitigation's marker is absent. It
does not show which algorithms a given handshake negotiates, which depends on the
peer and on the library's default lists, and that was not measured.

The fork's own four commits were reviewed. Two are a `.gitignore` and a lockfile.
`bdc906b9` fixes agent authentication when the server reports partial success.
`a169f627` moves `convertToMpint` into `utils.js` and applies it to the `r` and `s`
values in `sigSSHToASN1`; upstream did not normalise them, which made some valid
ECDSA signatures fail to parse. Neither weakens a check.

Reproduce:

```
grep -o '"ssh2": "[^"]*"' extension/package.json
gh api repos/jeanp413/ssh2/compare/jeanp413:master...mscdex:master --jq '.total_commits'
grep -o 'kex-strict-c-v00@openssh.com' extension/lib/extension.js | wc -l
grep -o chacha20-poly1305 extension/lib/extension.js | wc -l
```

### 3. Two forwarding listeners bind the unspecified address

Two servers are created for forwarding and both call `listen` with a port and no
bind address:

- `src/authResolver.ts:422` — the SOCKS server
- `src/ssh/sshConnection.ts:342` — the port-forward server

Node then binds the unspecified address rather than loopback. Measured on macOS
26.6.1 with Node 22.14.0, `net.createServer().listen(0)` reports
`{"address":"::","family":"IPv6"}`, which accepts connections arriving on any
interface. "Every interface" was the wording used here before; the accurate
statement is the unspecified address, with reachability then depending on the
host's own firewall.

`remote.SSH.enableDynamicForwarding` defaults to `true`
(`src/authResolver.ts:129`), so the SOCKS server, which has no authentication of
its own, is started by default. It exists while a remote session is being
resolved, not permanently, and its port is not fixed — the exposure is a listener
reachable off-host for the life of a session, not a standing open proxy.

The same bundle's own helpers pass `'127.0.0.1'` explicitly
(`src/common/ports.ts:15`, `:108`, `:116`, and `src/ssh/sshConnection.ts:412`), so
the omission is confined to the two call sites above.

A user who wants the SOCKS listener not to be created can set
`remote.SSH.enableDynamicForwarding` to `false`.

Reproduce:

```
grep -rn '\.listen\(' src/                       # two sites without an address
grep -n enableDynamicForwarding src/authResolver.ts
node -e "require('net').createServer().listen(0,function(){console.log(this.address());this.close()})"
```

### 4. The downloaded server archive has no independent signature or pinned digest

`src/scripts/server-setup.sh` (292 lines) downloads the server tarball and
extracts it. There is no signature check, no digest pinned in the extension, and
no digest remembered from a previous download; `tar -xO` is used to detect a
truncated archive. Integrity therefore rests entirely on TLS to the endpoint,
which does authenticate the endpoint and protect the bytes in transit — so this is
missing supply-chain hardening rather than an unprotected download.

The same limit applies to this project's own answer to it, and saying so here
rather than only in the design document is the point of recording it: digests
remembered on first use detect a later substitution and cannot detect a
substitution on the first fetch.

### 5. Lower-severity observations

- With `remote.SSH.serverValidation` set to `force`, the setup script rewrites the
  remote `product.json` commit field with `sed`
  (`src/scripts/server-setup.sh:227`).
- The composed `ProxyCommand` is written to the trace log
  (`src/authResolver.ts:215`), which discloses anything embedded in it to whoever
  can read that log. Trace logging is not on by default.
- `remote.SSH.serverValidation` set to `skip` passes `--disable-client-validation`
  (`src/serverSetup.ts:316`). An earlier revision of this document named the flag
  `--disable-client-side-validation` and claimed that, because Kiro's remote server
  does not have it, the setting prevents the server from starting. **Both parts
  were wrong.** The flag name is as above, and running Kiro's own remote server
  with it shows the flag is ignored and startup succeeds:

  ```
  Server bound to 127.0.0.1:36293 (IPv4)
  Extension host agent listening on 36293
  Ignoring option 'disable-client-validation': not supported for server.
  ```

  There is no availability problem here. The observation that remains is only that
  the flag has no effect on this server.

### Practices that were checked and no problem was found

Stated this way on purpose: these are paths that were inspected, not proofs of
absence.

No password or passphrase persistence was found in the paths inspected. `keytar`,
`SecretStorage` and `secrets.store` do not occur in the bundle and prompt results
are held in memory, which is consistent with no persistence but does not exclude a
mechanism under another name. `ProxyCommand` is executed with `spawn` and an
argument vector, parsed by a quote-aware parser, so there is no shell
interpolation. The remote server is started bound to `127.0.0.1`, its connection
token comes from `crypto.randomUUID` and is written to a file created `0600`, and
`--telemetry-level off` is passed.

## `saurav-z.vsc-ssh-extension` 1.1.0

These are compatibility observations, not security findings. The extension is
written for Visual Studio Code, and what follows is what happens when it is
installed into Kiro instead.

It declares an `ssh-remote` resolver but cannot complete a connection on Kiro,
for two independent reasons. Its `ServerManager` builds the download URL as
`https://update.code.visualstudio.com/commit:<commit>/server-<platform>/stable`,
taking `<commit>` from the running application's `package.json`. For a Kiro commit
that URL returns HTTP 404. As a control, the same URL for the Microsoft VS Code
stable commit `645f29cc3176500b4b5762ba887cf2a7f0ffdf2c` returns HTTP 200 with a
body of 216,833,164 bytes; re-checked in September 2026 for `server-darwin-arm64`
the length was 193,741,012 bytes, the difference being the platform in the path,
which the first measurement did not record. It installs into `~/.code-server` and
looks for a binary named `code-server`.

Separately, it requires the `resolvers`, `tunnels` and `terminalDataWriteEvent`
proposed APIs. Without the extension id in `enable-proposed-api` in
`~/.kiro/argv.json` it logs a warning and the resolver is never registered. This is
the documented behaviour of proposed APIs.

## `quanticware.vscodium-ssh-explorer` 0.2.10

Browses a remote file tree over SFTP. Its own description states that there is no
agent to install on the server. The window is not a remote window, so the
integrated terminal and any agent continue to run locally. This is the extension's
stated purpose and not a defect. It is recorded here because that difference —
remote files without a remote terminal — is the thing someone looking for a remote
window needs to know, and it is what made this project necessary rather than
optional.

## What the audit changed in this project's design

- SSH is delegated to the system `ssh` binary, so host key policy and key exchange
  policy are OpenSSH's and are updated with it (findings 1 and 2).
- No listener is created on a non-loopback address, and the primary channel creates
  no listener at all (finding 3).
- Archive digests are recorded on first use and enforced afterwards, and are
  checked before extraction rather than after — with the first-fetch limit stated
  in finding 4 and in SECURITY.md rather than left out (finding 4).
- The remote `product.json` is never rewritten, because making a mismatch
  disappear defeats the check that notices it (finding 5).
- Composed command lines are never logged (finding 5).

## Disclosure status

**These findings were published in this repository before the maintainer of
`jeanp413/open-remote-ssh` was notified, and that notification has not yet been
sent. This is not a coordinated disclosure, and publishing first was the wrong
order.** Recording that plainly is not a substitute for having done it the other
way round.

Threat model assumed: for findings 1 and 2, an attacker able to intercept traffic
on the network path; for finding 3, an attacker able to reach the user's machine
from a network it is attached to. Finding 4 assumes an attacker who can serve
different bytes than the vendor intended.

Mitigations available to a user today, which belong next to the findings rather
than after a fix: finding 3 can be avoided by setting
`remote.SSH.enableDynamicForwarding` to `false`. Findings 1 and 2 have no setting
that addresses them.

An earlier revision of this section claimed this document was the only place these
observations were written down. That claim is withdrawn: the upstream issue
tracker was not searched, and host key verification is a common enough subject
that prior reports should be assumed to exist until checked. This section will
record the report, the channel, and the response once it is filed.

Removing this file later would not undo its publication, because the content
remains in this repository's history.
