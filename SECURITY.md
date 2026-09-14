# Security

This extension runs commands on machines you connect to. That is a larger amount of
trust than most editor extensions ask for, so what it can do, what it will not do, and
what it cannot protect you from are written down here rather than left to be inferred.

## Reporting

Report anything you believe is a vulnerability through GitHub's private
vulnerability reporting on this repository, not as a public issue. A first
response should be expected within a week. There is no bounty.

## What the extension can do

- Run `ssh` as you, with your configuration, keys and agent.
- Execute a shell script on the remote host to install and start the editor's
  remote server, and run commands there for the duration of a session.
- Listen on `127.0.0.1` on your machine, on ports it chooses, to carry
  connections that remote extensions ask to have forwarded.

## What it will not do

These are checked by `npm run audit:supply-chain`, which runs in CI, so they fail
loudly rather than quietly:

- **No runtime dependencies.** The published archive contains this project's own
  code and nothing else. There is no vendored SSH implementation, and no
  third-party code executes as part of the extension.
- **No hardcoded network endpoints.** The only address it contacts is the one the
  host application publishes in its own `product.json`. There is no address in the
  shipped code at all.
- **No telemetry.** No analytics library is present, and the remote server is
  started with telemetry off.
- **A fixed file list in the published archive.** The manifest, the readme, this file,
  the licence, an icon, a `.gitignore`, and one bundled script. The check pins the list,
  so anything else appearing in it fails the build — which has already caught three
  files that had no business being shipped.
- **No install-time scripts.** Installing from source runs nothing.

And by construction:

- **No credential is sent to the host at all.** Signing in happens once per host, in
  the remote window. Two implementations of carrying it across were built and removed;
  [docs/DESIGN.md](docs/DESIGN.md) records why, including the consumer's refusal that
  settled it.
- **No listener on a non-loopback address**, and the connection to the remote
  server uses no local listener at all.
- **Secrets do not reach the log.** Tokens and composed command lines are never
  written to it.

## What it cannot protect you from

Saying this plainly matters more than the list above, because a document that only
lists defences is read as a claim of completeness.

- **Root on the remote host, or any other process running as your user there.** They
  can read whatever you sign in with on that host, and can see the remote server's
  connection token. Nothing here changes that; it is a property of using the machine.
- **What a remote extension does with a credential you give it there.** Once it has
  read one it can keep it in memory, pass it to a child, or write it somewhere, and
  nothing on this side can reach those copies.
- **Your own SSH configuration.** Host key policy, ciphers, agent forwarding and
  `ProxyCommand` are yours, and this extension inherits them deliberately. It does
  override forwarding and remote-command directives on its own connections so they
  cannot attach to them.
- **A compromised host application.** The extension reads the server's address
  from the application's `product.json` and trusts it.
- **The first fetch of a remote server build.** The vendor publishes no digest or
  signature, so a first install on a new commit trusts TLS to the vendor endpoint.
  Digests are recorded on first use and enforced afterwards, which catches a later
  substitution but not the first one.
- **The build itself.** Third-party code does run there, and saying otherwise would
  be the kind of claim this file exists to avoid. The release job fetches
  `@vscode/vsce` at a pinned version to produce the archive, and TypeScript, esbuild
  and the actions in the workflow all execute. What the checks above buy is narrower
  and worth stating exactly: no dependency's own install script runs, every action is
  pinned by commit digest, the packaging tool is not a standing dependency of the
  project, and the bundle that results is reproducible from source so a reader can
  rebuild it and compare rather than trust the machine that built it.

## Verifying a release

The bundled script is reproducible: check out the tag, run `npm ci --ignore-scripts`
and `node build.mjs`, and `dist/extension.js` will have the digest published with
the release. CI asserts this on every run.

The `.vsix` archive is not byte-reproducible, because a zip records timestamps.
Its digest is published to identify a build, and it carries a signed provenance
statement binding it to the commit and workflow that produced it:

```
gh attestation verify kiro-remote-ssh.vsix --repo littlemex/kiro-remote-ssh
```

## Threat model, in one sentence

This extension is written on the assumption that the machine you run the editor on
is yours and is not compromised, that the remote host is one you are entitled to
use but do not necessarily control, and that the network between them is not
trusted — which is why every SSH decision is delegated to OpenSSH and your own
configuration rather than reimplemented here.
