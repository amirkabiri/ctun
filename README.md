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

## Troubleshooting

A full operations guide ships with the README rewrite in task T4.6. Until
then, the most common issue operators hit is **orphan firewall rules**
left behind by a crashed or `kill -9`'d ctun process. ctun installs
per-OS firewall rules at startup (iptables on Linux, pf on macOS, netsh
on Windows) and removes them on SIGINT / SIGTERM / panic — but it
**cannot** intercept SIGKILL (`kill -9`), so a process killed that way
will leave its rules behind. The next ctun startup is idempotent and
will not duplicate the rule, but if you want to clear orphans manually
the per-OS recipe is below.

In every recipe, replace `<port>` with the tunnel port from your
config (`listen.addr`'s port on the server, `server.addr`'s port on
the client). ctun tags every rule it installs with `ctun-<port>` so
the recipes below remove only ctun's rules and leave unrelated host
firewall configuration untouched.

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

(`iptables -D` only removes one matching rule per invocation. Re-run
each line until iptables reports the rule is absent.)

The automated alternative: start ctun again with the same config, then
send it SIGTERM (`pkill -TERM ctun` or `kill -TERM <pid>`). ctun's
Apply is idempotent (it skips rules already present) and its Cleanup
removes every rule with the `ctun-<port>` tag, so this restores a
clean host firewall in two commands.

### macOS (pf)

ctun loads its rules into a named anchor `ctun.<port>`. Flush the
anchor to remove every rule:

```sh
sudo pfctl -a ctun.<port> -F all
```

Then remove ctun's anchor body tempfile from `/tmp`:

```sh
sudo rm -f /tmp/ctun-<port>.anchor
```

(The tempfile is harmless to leave behind — pf doesn't reference it
after the load — but cleaning it up keeps `/tmp` tidy.)

### Windows (netsh)

ctun's rule is named `ctun-<port>`. Delete it with:

```cmd
netsh advfirewall firewall delete rule name=ctun-<port>
```

Run from an elevated (Administrator) Command Prompt or PowerShell.
netsh exits with "No rules match the specified criteria." if the rule
was already removed — that's the harmless "already clean" case.

### Disabling auto-firewall management

If you manage host firewall rules with your own configuration
management (Ansible, Chef, Puppet, ...) and want ctun to leave them
alone, set:

```yaml
firewall:
  auto: false
```

in your ctun config. ctun will log one informational line at startup
reminding you the operator is responsible for installing the
equivalent rules manually, then proceed without touching the host
firewall. The per-OS rule recipes are documented in `docs/design-doc.md`
§12 (Persian) and in the comments at the top of
`internal/firewall/linux.go`, `darwin.go`, and `windows.go`.
