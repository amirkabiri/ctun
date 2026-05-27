# ctun

ctun tunnels SOCKS5 traffic over a stream of TCP **SYN packets only** — no
SYN-ACK, no full TCP handshake, no established TCP state on the wire. It's a
fork of [hanselime/paqet](https://github.com/hanselime/paqet) (MIT) with a new
security stack, a pluggable transport interface, automatic firewall management,
and a fixed binary wire format.

What ctun adds on top of paqet:

- **SYN-only transport with a TCP Fast Open option (Kind=34) on every SYN.**
  Every outbound SYN carries a Kind=34 option with an 8-byte HMAC cookie. The
  receive path drops anything without a valid Kind=34 option, so unrelated SYN
  traffic on the same port can't reach the inner protocol.
- **ChaCha20-Poly1305 + HKDF-SHA256 + 64-bit sliding-window anti-replay.**
  HELLO/HELLO_ACK handshake, per-session HMAC cookies, AEAD on every data
  frame, replay filter per session. Wrong PSK → silent drop, no RST.
- **Pluggable `Transport` interface and `ctun transports` subcommand.**
  Today only `syn-tfo` ships; Phase 6 adds SYN-ACK / UDP / raw-IP variants.
- **Automatic firewall management.** ctun installs the per-OS rules it needs
  (iptables on Linux, pf on macOS, netsh on Windows) at startup and removes
  them on SIGINT / SIGTERM. No more manual `iptables -t raw -A …` recipes.
- **Fixed binary wire format.** paqet's `encoding/gob` payloads are gone;
  every frame is `[SessionID:4][Sequence:8][Flags:1][Length:2][Payload:N]`,
  deterministic, fuzz-tested.

ctun's threat model, on-wire details, and security argument live in
[`docs/design-doc.md`](docs/design-doc.md) (Persian). The task-by-task
implementation plan lives in
[`docs/implementation-doc.md`](docs/implementation-doc.md) (English).

---

## Install

ctun is a single Go binary. It links against **libpcap** (Linux/macOS) or
**Npcap** (Windows) via cgo for the raw-packet send/receive path.

### Prerequisites

| OS      | Packet capture library                                       |
|---------|--------------------------------------------------------------|
| Linux   | `libpcap-dev` (Debian/Ubuntu) / `libpcap-devel` (RHEL/Fedora)|
| macOS   | libpcap ships with the base system; no install needed       |
| Windows | [Npcap](https://npcap.com) (install with WinPcap-compat mode)|

Go 1.21+ is required at build time. Root / Administrator privileges are
required at run time (raw sockets + pcap).

### Build from source

```sh
git clone https://github.com/hanselime/ctun.git
cd ctun
go build -o ctun ./
```

The binary is self-contained except for the libpcap/Npcap shared library.

### Install with `go install`

Once ctun is published to a module proxy:

```sh
go install ctun@latest
```

(Until then, build from source as above.)

---

## Quick start

ctun ships two example configs in `example/`. The minimum end-to-end path is
**server** → public host with a routable IP, **client** → laptop that exposes
a local SOCKS5 listener for browsers / curl / etc.

### Server

```sh
cp example/server.yaml.example server.yaml
# edit server.yaml: set network.interface, network.ipv4.addr,
# network.ipv4.router_mac, listen.addr, transport.kcp.key
sudo ./ctun run -c server.yaml
```

The server binds to `listen.addr` for incoming SYN packets, installs its
firewall rules (kernel-RST suppression on the tunnel port — see
[Firewall behaviour](#firewall-behaviour)), and waits for client handshakes.

### Client

```sh
cp example/client.yaml.example client.yaml
# edit client.yaml: set network.interface, network.ipv4.addr,
# network.ipv4.router_mac, server.addr, transport.kcp.key
# (key MUST match the server's transport.kcp.key)
sudo ./ctun run -c client.yaml
```

The client exposes a SOCKS5 listener on `socks5[0].listen` (default
`127.0.0.1:1080`). Point any SOCKS5-aware tool at it:

```sh
curl --socks5 127.0.0.1:1080 https://example.com/
```

Traffic from curl → SOCKS5 listener → SYN-tunnel → server → upstream.

A minimal `cipher: chacha20poly1305` config (the recommended setup, not the
plaintext-payload default that ctun inherits from paqet) is in
`test/integration/fixtures/server-syntfo.yaml` and `client-syntfo.yaml`.

### CLI surface

ctun is configured via a YAML file; there is no separate `server` /
`client` subcommand. The same binary runs both roles, chosen by the `role:`
field in the config.

```
ctun run        -c <config.yaml>     # run server or client per role:
ctun transports                       # list compiled-in transports
ctun secret                           # generate a 32-byte PSK
ctun version                          # print version
ctun ping       <opts>                # diagnostic: one raw TCP packet
ctun dump       <opts>                # diagnostic: log TCP payloads on a port
ctun iface                            # list available pcap interfaces
```

`./ctun --help` and `./ctun <subcommand> --help` are the source of truth for
flags.

---

## Configuration

The YAML schema is shared between server and client; the `role:` field selects
which fields are required. The example files in `example/` are heavily
commented — refer to those for the full surface area. The summary below covers
the load-bearing keys.

### Top-level keys

| Key              | Type           | Purpose                                                                  |
|------------------|----------------|--------------------------------------------------------------------------|
| `role`           | string         | `"server"` or `"client"`. Required.                                      |
| `log.level`      | string         | `none` / `debug` / `info` / `warn` / `error` / `fatal`. Default `info`.  |
| `transport_impl` | string         | Transport implementation name. Default `"syn-tfo"`. See `ctun transports`.|
| `cipher`         | string         | Outer AEAD: `""` (none) or `"chacha20poly1305"`. Default `""`.           |
| `network`        | object         | Interface / addressing / TCP-flag profile. See below.                    |
| `socks5`         | list           | (client) SOCKS5 listeners. See below.                                    |
| `forward`        | list           | (client) Static port-forward rules. Optional.                            |
| `listen`         | object         | (server) Tunnel listen address. `addr: ":9999"`.                         |
| `server`         | object         | (client) Tunnel server address. `addr: "1.2.3.4:9999"`.                  |
| `transport.kcp`  | object         | KCP and pre-shared key. See below.                                       |
| `firewall`       | object         | Automatic firewall behaviour. See below.                                 |

### `network`

```yaml
network:
  interface: "eth0"              # pcap interface name (eth0 / en0 / wlan0 / ...)
  guid: "\\Device\\NPF_{...}"    # Windows / Npcap only
  ipv4:
    addr: "10.0.0.100:9999"      # local IPv4 + port (server: matches listen.addr; client: 0 = ephemeral)
    router_mac: "aa:bb:cc:dd:ee:ff"  # gateway MAC; required by pcap injection
  ipv6:                          # optional, mirrors ipv4
    addr: "[::1]:9999"
    router_mac: "aa:bb:cc:dd:ee:ff"
  tcp:
    local_flag:  ["S"]           # TCP flags ctun stamps on outbound packets
    remote_flag: ["S"]           # TCP flags ctun expects on inbound (client only)
  pcap:
    sockbuf: 8388608             # OS pcap buffer (8 MiB server / 4 MiB client default)
```

`local_flag: ["S"]` is the SYN-only profile this fork is built for. paqet's
default of `["PA"]` (Push+Ack) still works if you want the upstream behaviour,
but the SYN-TFO transport assumes SYN packets and the firewall rules ctun
installs are SYN-oriented.

### `socks5` (client)

```yaml
socks5:
  - listen:   "127.0.0.1:1080"   # SOCKS5 listen address (loopback recommended)
    username: ""                 # optional auth (leave empty for unauthenticated)
    password: ""
```

You may declare multiple SOCKS5 listeners; each is independent.

### `server` / `listen`

```yaml
# server side
listen:
  addr: ":9999"                  # bind on all interfaces, port matches network.ipv4.addr port

# client side
server:
  addr: "1.2.3.4:9999"           # public server IP + port; client side
```

### `transport.kcp`

The KCP block tunes the reliable-stream layer on top of the SYN transport.
See `example/server.yaml.example` for the full knob list and per-mode defaults
(`mode: fast` / `fast2` / `fast3` / `normal` / `manual`). The fields you must
set:

```yaml
transport:
  protocol: "kcp"
  conn: 1                        # parallel KCP connections (1-256)
  kcp:
    mode: "fast"
    key: "your-secret-key-here"  # PSK; MUST match between client and server
    # block: "aes"               # optional kcp-go BlockCrypt — independent of top-level cipher
```

The `key` here is the pre-shared secret. Generate one with `./ctun secret`.

### `firewall`

```yaml
firewall:
  auto: true                     # default: install rules at startup, remove on SIGINT/SIGTERM
  backend: "auto"                # auto / iptables / pf / netsh / none
```

Setting `auto: false` (or `backend: "none"`) disables automatic management
entirely. See [Firewall behaviour](#firewall-behaviour).

---

## Firewall behaviour

ctun crafts raw TCP packets via libpcap; the host kernel must be told to
ignore them, or it will RST the synthetic flow as soon as the first
unexpected SYN lands. paqet documented a manual recipe in its README; ctun
ships that recipe as code.

At startup, ctun's `firewall` package detects the host OS and applies the
appropriate per-port rules:

| OS      | Backend         | What ctun installs                                                                  |
|---------|-----------------|-------------------------------------------------------------------------------------|
| Linux   | `iptables`      | `raw PREROUTING / OUTPUT NOTRACK` on the tunnel port; `mangle OUTPUT … RST DROP` on the server. |
| macOS   | `pf` (`pfctl`)  | Loaded into a named anchor `ctun.<port>` so cleanup is `pfctl -a ctun.<port> -F all`. |
| Windows | `netsh advfirewall` | A rule named `ctun-<port>` blocking inbound TCP on the tunnel port from the kernel side. |

Every rule is tagged (`-m comment --comment ctun-<port>` on iptables, anchor
name on pf, rule name on netsh) so ctun's cleanup removes only its own rules
and leaves unrelated host firewall configuration alone.

**Apply is idempotent.** Restarting ctun after a clean (or unclean) shutdown
will not duplicate rules.

**Cleanup runs on every controlled exit path**: clean return, SIGINT, SIGTERM,
and panic recovery. The known gap is **SIGKILL** (`kill -9`) — Linux gives no
chance to intercept it, so a hard-killed ctun process leaves its rules behind.
See [Troubleshooting](#troubleshooting) for the per-OS manual cleanup recipes.

If you manage host firewall rules via your own configuration management
(Ansible, Chef, Puppet, …), set `firewall.auto: false` in the YAML and install
equivalent rules yourself. ctun will log one informational line at startup
reminding you of that responsibility, then leave the host firewall alone.

---

## Troubleshooting

The most common operational issue is **orphan firewall rules** left behind by
a crashed or `kill -9`'d ctun process. ctun installs per-OS firewall rules at
startup (iptables on Linux, pf on macOS, netsh on Windows) and removes them on
SIGINT / SIGTERM / panic — but it **cannot** intercept SIGKILL (`kill -9`),
so a process killed that way will leave its rules behind. The next ctun
startup is idempotent and will not duplicate the rule, but if you want to
clear orphans manually the per-OS recipe is below.

In every recipe, replace `<port>` with the tunnel port from your config
(`listen.addr`'s port on the server, `server.addr`'s port on the client).
ctun tags every rule it installs with `ctun-<port>` so the recipes below
remove only ctun's rules and leave unrelated host firewall configuration
untouched.

### Linux (iptables)

List ctun's rules so you can see what's installed:

```sh
sudo iptables -t raw    -L PREROUTING -n --line-numbers | grep ctun-<port>
sudo iptables -t raw    -L OUTPUT     -n --line-numbers | grep ctun-<port>
sudo iptables -t mangle -L OUTPUT     -n --line-numbers | grep ctun-<port>   # server only
```

Delete each orphan rule by matching on the comment tag:

```sh
sudo iptables -t raw    -D PREROUTING -p tcp --dport <port> -m comment --comment ctun-<port> -j NOTRACK
sudo iptables -t raw    -D OUTPUT     -p tcp --sport <port> -m comment --comment ctun-<port> -j NOTRACK
sudo iptables -t mangle -D OUTPUT     -p tcp --sport <port> --tcp-flags RST RST -m comment --comment ctun-<port> -j DROP   # server only
```

(`iptables -D` only removes one matching rule per invocation. Re-run each
line until iptables reports the rule is absent.)

The automated alternative: start ctun again with the same config, then send
it SIGTERM (`pkill -TERM ctun` or `kill -TERM <pid>`). ctun's Apply is
idempotent (it skips rules already present) and its Cleanup removes every
rule with the `ctun-<port>` tag, so this restores a clean host firewall in
two commands.

### macOS (pf)

ctun loads its rules into a named anchor `ctun.<port>`. Flush the anchor to
remove every rule:

```sh
sudo pfctl -a ctun.<port> -F all
```

Then remove ctun's anchor body tempfile from `/tmp`:

```sh
sudo rm -f /tmp/ctun-<port>.anchor
```

(The tempfile is harmless to leave behind — pf doesn't reference it after the
load — but cleaning it up keeps `/tmp` tidy.)

### Windows (netsh)

ctun's rule is named `ctun-<port>`. Delete it with:

```cmd
netsh advfirewall firewall delete rule name=ctun-<port>
```

Run from an elevated (Administrator) Command Prompt or PowerShell. netsh
exits with "No rules match the specified criteria." if the rule was already
removed — that's the harmless "already clean" case.

### Disabling auto-firewall management

If you manage host firewall rules with your own configuration management
(Ansible, Chef, Puppet, …) and want ctun to leave them alone, set:

```yaml
firewall:
  auto: false
```

in your ctun config. ctun will log one informational line at startup
reminding you the operator is responsible for installing the equivalent
rules manually, then proceed without touching the host firewall. The per-OS
rule recipes are documented in `docs/design-doc.md` §12 (Persian) and in
the comments at the top of `internal/firewall/linux.go`, `darwin.go`, and
`windows.go`.

### Other common issues

- **`Error: cannot open interface`** — the configured `network.interface`
  doesn't exist or your user lacks pcap capability. Run `./ctun iface` to
  list available interfaces; on Linux use `sudo` or grant `CAP_NET_RAW` +
  `CAP_NET_ADMIN`.
- **Client connects but no traffic flows** — verify `transport.kcp.key`
  matches between server and client. Wrong key triggers the silent-drop
  branch of the handshake and you'll see nothing on the server side.
- **macOS `lo0` integration tests fail to inject** — loopback on macOS uses
  the DLT_NULL link type, not Ethernet; the integration suite is documented
  as Linux-only because of this. Real traffic on `en0` / a wired interface
  works fine.

---

## Upstream tracking

This repository tracks paqet as a read-only `upstream` remote so you can pull
fixes that land upstream:

```sh
git fetch upstream
git log upstream/master --oneline -20    # inspect upstream changes
# then cherry-pick or merge as needed
```

Do not push to the upstream remote.

---

## License & attribution

ctun is MIT-licensed; see [`LICENSE`](LICENSE).

ctun is a fork of [hanselime/paqet](https://github.com/hanselime/paqet)
(MIT). The upstream packet I/O plumbing — pcap send/receive handles, the
KCP smux integration, the SOCKS5 listener — is paqet's work. See
[`NOTICE`](NOTICE) for the upstream commit SHA the fork is based on.

**Modifications from upstream paqet** (see
[`docs/design-doc.md`](docs/design-doc.md) and
[`docs/implementation-doc.md`](docs/implementation-doc.md) for the full
rationale):

- SYN-only profile with a mandatory TCP Fast Open (Kind=34) option on every
  packet, plus a receive-side Kind=34 gate that drops anything else.
- A `Transport` interface and registry; the SYN-TFO path is the first
  implementation.
- ChaCha20-Poly1305 + HKDF-SHA256 + 64-bit sliding-window anti-replay
  applied to every data frame, gated by a HELLO/HELLO_ACK handshake.
- A fixed binary wire format
  (`[SessionID:4][Sequence:8][Flags:1][Length:2][Payload:N]`) replacing
  paqet's `encoding/gob` payloads.
- Automatic per-OS firewall rule management with signal-driven cleanup,
  replacing paqet's manual `iptables` recipe in the server README.
