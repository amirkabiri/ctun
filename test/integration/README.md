# ctun integration tests

End-to-end tests that drive the compiled `ctun` binary as one or more
subprocesses. They are deliberately heavy: each one builds the binary,
launches the server and client, drives traffic through the tunnel, and tears
everything down.

## Requirements

- **Root / sudo.** Opening pcap handles on loopback requires `CAP_NET_RAW`
  (Linux) or root (macOS). Without root the suite skips itself with a clear
  message rather than failing.
- **libpcap.** Linked via cgo through `github.com/gopacket/gopacket/pcap`.
  - macOS: provided by the Xcode Command Line Tools — no extra install.
  - Linux: `apt install libpcap-dev` (or distro equivalent).
- **Go toolchain** matching the version pinned in `go.mod`.

## Running

From the repository root:

```bash
# Default — skips cleanly without root.
go test ./test/integration/ -v

# Full run, macOS / Linux:
sudo go test ./test/integration/ -v

# SYN-TFO end-to-end (the canonical Phase-1 integration test):
sudo go test ./test/integration/ -run Smoke_SynTfo -v

# Phase-3 secure-tunnel suite (sudo for the full-stack tests; non-sudo
# in-memory variants always run):
sudo go test ./test/integration/ -run SecureTunnel -v
go test ./test/integration/ -run SecureTunnel -v

# Just the baseline (quarantined — SKIPs immediately):
sudo go test ./test/integration/ -run Smoke_PaqetBaseline -v

# Just the SYN-only (quarantined — SKIPs immediately):
sudo go test ./test/integration/ -run Smoke_SynOnly -v

# A single sub-iteration:
sudo go test ./test/integration/ -run 'Smoke_SynTfo/first-run' -v
```

The suite is also skipped under `-short`, so plain `go test -short ./...` from
a contributor laptop is always safe:

```bash
go test -short ./...
```

## What the suite covers today

- `Smoke_SynTfo` — the canonical Phase-1 integration test. Boots the ctun
  server + client with `transport_impl: "syn-tfo"` on loopback, drives an
  HTTP GET through the SOCKS5 listener, and asserts both (a) the expected
  response body and (b) that at least one captured SYN packet on the tunnel
  port carries a TCP option with Kind=34 and OptionLength=10 — the on-wire
  signature of the syntfo transport's TFO option. Runs `first-run` and
  `second-run` in a single `go test` invocation so teardown leaks surface on
  the second iteration. T4.5's CI matrix is expected to wire this test in as
  the Phase-1 integration gate.

- `Test_AntiReplay_ClientSendsN_AttackerReinjectsFirst` (T3.4, runs without
  sudo) — wires two syntfo secureConn halves through an in-memory pipe,
  sends N legitimate packets, has an "attacker" re-inject the first sealed
  bytes mid-stream, and asserts every payload was processed exactly once,
  the replay counter ticked exactly once, and no AEAD-open-fail or
  unknown-session drops occurred. Skipped under `-short`.

- `Test_SecureTunnel` (T3.5, sudo-gated) — Phase-3 end-to-end secure tunnel.
  Boots ctun server + client with `cipher: chacha20poly1305` and
  `transport_impl: "syn-tfo"` and exercises the full stack (SYN-TFO +
  ChaCha20-Poly1305 + HKDF + anti-replay + HELLO/HELLO_ACK handshake) by
  driving an HTTP GET through the SOCKS5 listener and asserting the
  expected body. Runs `first-run` and `second-run` like `Smoke_SynTfo`.

- `Test_SecureTunnel_WrongPSK_ServerSilent` (T3.5, sudo-gated) — boots
  server and client with mismatched PSKs, drives an HTTP request through
  SOCKS5, asserts the client request times out within ~20 s, and confirms
  via pcap that the server emitted zero packets from its tunnel port —
  the design-doc §8.4 "silent drop" property.

- `Test_SecureTunnel_WrongPSK_HandshakeFails` (T3.5, runs without sudo) —
  in-memory variant of the wrong-PSK case. Drives `RunClientHandshake`
  with a `Sender` that pushes HELLOs into a channel processed by a
  `RunServerHandshake` goroutine using a mismatched authKey. Asserts the
  client returns `ErrHandshakeTimeout` / `DeadlineExceeded` and the server
  emitted zero HELLO_ACK bytes. Skipped under `-short`.

- `Test_SecureTunnel_TamperedCiphertext_DropAndRecover` (T3.5, runs without
  sudo) — in-memory variant exercising "byte flipped in flight". Sends a
  packet, flips a byte past the AEAD nonce while it sits in the receiver's
  inbox, sends a clean follow-up packet, asserts the AEAD-open-fail
  counter ticked once and the clean payload round-tripped. Skipped under
  `-short`.

## Quarantined (skipped)

These tests are kept on disk for reference until T4.6 deletes them. Each one
unconditionally calls `t.Skip("superseded by Test_Smoke_SynTfo; will be
deleted in T4.6")` at the top of its `Test_Smoke_*` function, so the suite
still compiles and lists them — they simply report `SKIP` immediately.

- `Smoke_PaqetBaseline` — Phase 0 baseline with `local_flag: ["PA"]` (paqet
  defaults). Superseded by `Smoke_SynTfo`; T4.6 deletes the file and its
  fixtures (`fixtures/server-pa.yaml`, `fixtures/client-pa.yaml`).
- `Smoke_SynOnly` — T0.3 feasibility probe with `local_flag: ["S"]`.
  Superseded by `Smoke_SynTfo`; T4.6 deletes the file and its fixtures
  (`fixtures/server-s.yaml`, `fixtures/client-s.yaml`).

## Configuration knobs

- `CTUN_TEST_IFACE` — override the pcap interface. Defaults to `lo0` on
  Darwin/BSD and `lo` on Linux. Set this if your loopback is named something
  else, e.g. inside a network namespace.

## Test isolation guarantees

Each iteration:

- allocates a fresh pair of TCP ports by probing `127.0.0.1:0` on the kernel,
- materialises its YAML fixtures into `t.TempDir()` with a per-iteration
  shared key,
- spawns server and client in their own process group (so a misfired SIGTERM
  cannot wander back into `go test`),
- registers `t.Cleanup` handlers that SIGTERM the children, drain their wait
  channels, and fall through to SIGKILL on a 5-second deadline.

There is **no** global state and no shared scratch directory between
iterations. Re-runs are independent.

## Diagnostics

Subprocess stdout and stderr are captured into a goroutine-safe buffer. On
test failure the buffer is dumped to the test log. Tail the verbose output
(`-v`) if you need to see what the binary said.

## When a test starts failing

1. Confirm you're root and `libpcap` is installed.
2. Confirm no other process is bound to the loopback ports the test allocated
   between probe and subprocess startup (rare but possible on a busy machine —
   the port allocator races against the kernel here by design).
3. Run with `-v` and copy the subprocess output into the bug report.
4. Re-run with a single sub-test (`-run 'Smoke_PaqetBaseline/first-run'`) to
   bisect first-run vs. second-run failures.

## Adding new integration tests

- One test file per phase / feature area.
- Re-use the helpers in `smoke_paqet_baseline_test.go` (`startCtun`,
  `allocLoopbackPorts`, `doHTTPThroughSOCKS5`, etc.); promote them to a shared
  file once a third test needs them.
- Always go through `skipUnlessRunnable(t)` first so non-root contributors are
  never blocked by integration prereqs.
- Always allocate ports through the probe helper; never hard-code.
- Always materialise fixtures into `t.TempDir()`.
