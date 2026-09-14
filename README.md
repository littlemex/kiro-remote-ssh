# Remote - SSH for Kiro

Open a folder on a remote Linux host over SSH, so that the editor, the integrated
terminal, workspace extensions and the Kiro agent all run on that host.

Kiro publishes a remote extension host but no extension that connects to one.
This is the client half.

## Status

Early. The remote bootstrap has been exercised on a real host; the editor-side
connection is under verification. See [docs/DESIGN.md](docs/DESIGN.md) for what is
built and what is deliberately not, and [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)
for the audit of existing options that decided the design.

## Requirements

- An OpenSSH client, 8.4 or newer, on your `PATH`. No other SSH client is
  supported, and none is bundled.
- A remote host running Linux on x64 or arm64 with glibc. Kiro publishes no
  remote server for macOS, and the published server is not a musl build.
- The `resolvers` API proposal enabled for this extension. Add
  `"enable-proposed-api": ["littlemex.kiro-remote-ssh"]` to `argv.json` and
  restart.

## How it connects

All SSH work is done by your own `ssh`, which means your `known_hosts`, your
keys and agent, and your `ProxyCommand` or `ProxyJump` all apply unchanged. A
host reachable only through a bastion needs no configuration here.

Everything for one host is multiplexed onto a single SSH connection, so you
authenticate once. The channel to the remote extension host is a byte stream over
that connection rather than a forwarded local port, so this extension opens no
listening socket on your machine for it.

## Build

```
npm install
npm run package
kiro --install-extension kiro-remote-ssh-0.1.0.vsix
```

## License

Apache-2.0.
