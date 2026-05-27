# ctun

ctun is a fork of [paqet](https://github.com/hanselime/paqet) (MIT) that
tunnels SOCKS5 traffic over a stream of TCP SYN packets only — no SYN-ACKs,
no full TCP handshakes. It layers a TCP Fast Open option (Kind=34) on every
SYN, a ChaCha20-Poly1305 + HKDF + anti-replay security stack, automatic
firewall rule management on Linux/macOS/Windows, and a fixed binary wire
format on top of paqet's existing raw-socket plumbing. A full README is
coming in task T4.6; until then, see `docs/design-doc.md` and
`docs/implementation-doc.md` for what is being built.

## Upstream tracking

This repository tracks paqet as a read-only `upstream` remote so you can pull
fixes that land upstream. To fetch the latest:

```sh
git fetch upstream
git log upstream/master --oneline -20    # inspect upstream changes
# then cherry-pick or merge as needed
```

The `upstream` remote is configured automatically by the bootstrap commit.
Do not push to it; ctun has no `origin` configured yet.
