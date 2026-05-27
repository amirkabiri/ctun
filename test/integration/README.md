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

# Just the baseline:
sudo go test ./test/integration/ -run Smoke_PaqetBaseline -v

# A single sub-iteration:
sudo go test ./test/integration/ -run 'Smoke_PaqetBaseline/first-run' -v
```

The suite is also skipped under `-short`, so plain `go test -short ./...` from
a contributor laptop is always safe:

```bash
go test -short ./...
```

## What the suite covers today

- `Smoke_PaqetBaseline` — boots the unmodified-default ctun server + client
  (paqet's `local_flag: ["PA"]` flag profile) on loopback, drives an HTTP GET
  through the SOCKS5 listener, and asserts the body. Runs the full
  boot/round-trip/teardown cycle **twice** in a single `go test` invocation to
  prove that ports, pcap handles, and child processes don't leak across runs.
  This test is a Phase 0 baseline — T1.5 supersedes it with a SYN-only variant
  and T4.6 deletes it. Do not extend it with feature coverage; add new tests
  alongside instead.

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
