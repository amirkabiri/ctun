# ctun — Implementation Document

**Version:** 1.0
**Date:** 2026-05-27
**Companion to:** [design-doc.md](./design-doc.md) v2.0
**Status:** Active

---

## Purpose

This document breaks the [design doc](./design-doc.md) into discrete, sequenced engineering tasks. Each task has an explicit **scope**, **files touched**, **dependencies**, and a **Definition of Done (DoD)** so any engineer can pick one up and know exactly when they are finished.

## How to use this document

- Tasks are numbered `T<phase>.<seq>` (e.g. `T1.3`).
- Work within a phase can be parallelized **only** where the dependency column is empty for both tasks. Otherwise complete dependencies first.
- A task is **not done** until every box in its DoD is checked, every test listed under Verification passes, and the change is on a branch named `ctun/<task-id>-<slug>` ready for review.
- When a task uncovers work that does not fit its DoD, file a follow-up task at the bottom of the appropriate phase rather than scope-creeping.

## Conventions

- **Branch naming:** `ctun/T<id>-<short-slug>` (e.g. `ctun/T1.2-tfo-option`).
- **Commit prefix:** `[T<id>] <subject>` (e.g. `[T1.2] add TFO option to SYN crafter`).
- **Test layout:** every package gets a `*_test.go`; integration tests under `test/integration/`.
- **Code style:** `gofmt -s`, `goimports`, `golangci-lint run` clean. No new lint warnings.
- **No CGO disablement** unless the task explicitly says so (Phase 5).
- **DoD checkboxes:** copy the DoD list into the PR description and tick them as you finish.

---

## Phase 0 — Fork & Bootstrap

**Goal:** Get a buildable `ctun` binary derived from paqet that runs end-to-end with `local_flag: ["S"]` before we touch any logic.

**Exit criteria:** A SOCKS5 → SYN-only tunnel → internet round trip succeeds using upstream paqet code, only renamed.

---

### T0.1 — Fork repo and rename module

**Scope:** Create the `ctun` repo from `hanselime/paqet` and rename the Go module so all imports resolve under `ctun/`.

**Files touched:**
- `go.mod` (module path)
- Every `*.go` file with `paqet/...` imports
- `Makefile`, `.github/workflows/*.yml` (binary name `paqet` → `ctun`)
- `LICENSE` (keep) and new `NOTICE` file
- `README.md` (replace with stub mentioning the fork; full README is a later task)

**Dependencies:** none

**DoD:**
- [ ] Repo `<owner>/ctun` exists on GitHub, forked from `hanselime/paqet`.
- [ ] `git remote add upstream https://github.com/hanselime/paqet.git` configured locally and documented in `CONTRIBUTING.md`.
- [ ] `go.mod` declares `module ctun`.
- [ ] `grep -r "paqet/" --include="*.go"` returns zero results.
- [ ] `go build -o ctun ./` succeeds on Linux and macOS.
- [ ] `./ctun --help` runs and prints all subcommands inherited from paqet (`server`, `client`, `ping`, `dump`, `secret`).
- [ ] `NOTICE` file attributes paqet (MIT) and lists the upstream commit SHA used as the fork base.
- [ ] CI workflow renamed jobs and artifacts to `ctun_*`.

**Verification:**
```bash
go test ./...                # all upstream tests still pass
./ctun secret                # generates a key
./ctun --version             # prints version stamped by ldflags
```

---

### T0.2 — Baseline end-to-end smoke test with paqet defaults

**Scope:** Confirm the unmodified fork can carry traffic with paqet's default `local_flag: ["PA"]` so any later breakage is traceable to ctun changes, not the inherited code.

**Files touched:**
- `test/integration/smoke_paqet_baseline_test.go` (new)
- `test/integration/fixtures/server-pa.yaml`, `client-pa.yaml`

**Dependencies:** T0.1

**DoD:**
- [ ] Integration test spins up server and client locally on loopback (or two Docker containers with a veth pair on Linux).
- [ ] Test issues an HTTP GET through the SOCKS5 listener and asserts a 200 response from a known endpoint (a local test HTTP server in the same harness).
- [ ] Test cleans up firewall rules and processes on teardown — runs cleanly twice in a row.
- [ ] Documented in `test/integration/README.md` how to run locally (must be root / sudo).

**Verification:** `sudo go test ./test/integration/ -run Smoke_PaqetBaseline -v` passes twice consecutively.

---

### T0.3 — SYN-only feasibility check

**Scope:** Repeat T0.2 with `local_flag: ["S"]` and `remote_flag: ["S"]` to discover up-front whether paqet's flag cycling is fully wired for SYN-only or whether bugs exist that Phase 1 must fix. This is a **diagnostic** task — the goal is the report, not a fix.

**Files touched:**
- `test/integration/smoke_syn_only_test.go` (new, may be marked `t.Skip` if it fails)
- `docs/findings/T0.3-syn-only-feasibility.md` (new, brief)

**Dependencies:** T0.2

**DoD:**
- [ ] Test attempts a HTTP GET through SOCKS5 with both flags set to `["S"]`.
- [ ] Findings doc records: pass/fail, any panics, packet capture evidence (`tcpdump` excerpt) of what was actually emitted on the wire.
- [ ] If the test fails, the report lists the smallest reproducer and the suspected file in `internal/socket/` to be fixed in Phase 1.
- [ ] If the test passes, it is enabled (no `t.Skip`) and added to CI's integration job.

**Verification:** The findings doc is reviewed and merged. CI runs the test (passing or skipping) without crashing the suite.

---

## Phase 1 — Transport Interface + TFO Option

**Goal:** Refactor packet I/O into a pluggable Transport, then add the TCP Fast Open option that distinguishes ctun traffic from raw "SYN with payload."

**Exit criteria:** `ctun transports` lists `syn-tfo`; SYN packets on the wire carry a valid Kind=34 option with an HMAC cookie; only packets with valid cookies are accepted.

---

### T1.1 — Extract `Transport` interface and registry

**Scope:** Introduce `internal/transport/` with the formal `Transport` interface, `Factory`, `Config`, and `Register/New` registry. Refactor the existing `internal/socket/` flow into the first registered transport. No behavior change yet.

**Files touched:**
- `internal/transport/transport.go` (new — interface + registry)
- `internal/transport/transport_test.go` (new — registry round-trip)
- `internal/socket/*.go` (no rename yet, but wrapped so it satisfies `Transport`)
- `internal/client/`, `internal/server/` (call `transport.New("syn-tfo", cfg)` instead of constructing `socket.PacketConn` directly)
- `internal/conf/` (add `Transport string` field, default `"syn-tfo"`)

**Dependencies:** T0.3 (must know what works first)

**DoD:**
- [ ] Interface matches the design doc §7.1 exactly (`Send`, `Recv`, `LocalAddr`, `Close`).
- [ ] Registry rejects unknown names with a clear error.
- [ ] An `init()` in the SYN-TFO subpackage calls `transport.Register("syn-tfo", New)`.
- [ ] All client/server call sites go through `transport.New(name, cfg)`.
- [ ] `internal/socket/PacketConn` is gone OR is a thin internal helper to the SYN-TFO transport, not referenced from outside its package.
- [ ] Unit test demonstrates two stub transports can be registered, retrieved, and one can be passed to the upper layers as a `net.PacketConn`-like consumer.
- [ ] All previously passing tests still pass (no regressions).

**Verification:**
```bash
go test ./internal/transport/... -v
sudo go test ./test/integration/ -v          # baseline must still pass
```

---

### T1.2 — Add TFO option (Kind=34) on send path

**Scope:** When the SYN-TFO transport sends a packet, append a TCP option `Kind=34, Length=10, Cookie=8 bytes` to the TCP header. The cookie value comes from a `CookieProvider` interface, stubbed in this task (returns a constant) and implemented properly in T3.2.

**Files touched:**
- `internal/transport/syntfo/send.go` (new home for the send logic)
- `internal/transport/syntfo/cookie.go` (new — `CookieProvider` interface + `StaticCookieProvider` stub)
- `internal/transport/syntfo/send_test.go` (new)

**Dependencies:** T1.1

**DoD:**
- [ ] Every emitted SYN packet contains exactly one TCP option with `Kind=34` and `OptionLength=10`.
- [ ] Cookie is exactly 8 bytes; option payload area is exactly 8 bytes.
- [ ] TCP checksum recomputed correctly after option addition (verified by parsing the emitted bytes with `gopacket` and re-running checksum).
- [ ] Total TCP header (including all options) is a multiple of 4 bytes; pad with `Kind=1` (NOP) if needed.
- [ ] MSS option still present and unchanged.
- [ ] `CookieProvider` interface lives in a place both send and receive can import without cycles.
- [ ] Unit test asserts the serialized packet's TCP options byte-for-byte for a fixed input.

**Verification:**
```bash
go test ./internal/transport/syntfo/... -run TestSend -v
# manual capture (Linux):
sudo ./ctun server --config example/server.yaml &
sudo tcpdump -i lo -X -c 5 'tcp[tcpflags] & tcp-syn != 0'
# confirm "Kind: Unknown (34)" appears in tcpdump's option dump
```

---

### T1.3 — Accept only SYN packets with a valid TFO option on receive path

**Scope:** On receive, drop any packet that does not have a TCP option `Kind=34` of length 10. Cookie *validation* is also stubbed here (accept-all from the `CookieProvider`) — real validation lands in T3.2.

**Files touched:**
- `internal/transport/syntfo/recv.go` (new)
- `internal/transport/syntfo/recv_test.go` (new)

**Dependencies:** T1.2

**DoD:**
- [ ] Packets without `Kind=34` are dropped silently (no log spam on the hot path; metrics counter `dropped_no_tfo` instead).
- [ ] Packets with malformed option length are dropped.
- [ ] Packets with valid option shape are passed to the next layer regardless of cookie value (validation deferred to T3.2).
- [ ] Hot-path allocation budget: zero allocations per accepted packet in the steady state (`go test -benchmem` shows 0 allocs/op for `decodeTFO`).
- [ ] Unit tests cover: no options, only MSS, only Kind=34 with wrong length, valid Kind=34, multiple options including Kind=34.

**Verification:**
```bash
go test ./internal/transport/syntfo/... -run TestRecv -v
go test -bench=BenchmarkDecodeTFO -benchmem ./internal/transport/syntfo/
```

---

### T1.4 — `ctun transports` subcommand

**Scope:** A simple read-only command that prints the names of registered transports.

**Files touched:**
- `cmd/transports.go` (new)

**Dependencies:** T1.1

**DoD:**
- [ ] `ctun transports` prints one transport name per line, sorted.
- [ ] Output format is stable and grep-friendly (no decorative table by default).
- [ ] `--json` flag emits a JSON array.
- [ ] Help text mentions that more transports may be added by recompiling with additional `import _` lines.

**Verification:** `./ctun transports` and `./ctun transports --json` produce the expected output.

---

### T1.5 — End-to-end SYN-TFO smoke test

**Scope:** Replace the Phase 0 baseline test with a SYN-TFO version that asserts both the TFO option presence on the wire and a successful HTTP round trip.

**Files touched:**
- `test/integration/smoke_syn_tfo_test.go` (new)
- Remove or quarantine `smoke_paqet_baseline_test.go` (kept under `t.Skip` for reference; remove in Phase 4 cleanup).

**Dependencies:** T1.2, T1.3, T1.4

**DoD:**
- [ ] Test boots client + server with `transport: syn-tfo`, sends an HTTP request, asserts 200.
- [ ] Test uses `gopacket/pcap` to sniff loopback and asserts at least one captured SYN packet from the client has a Kind=34 option.
- [ ] Test passes deterministically twice in a row.
- [ ] CI integration job runs this test on Linux.

**Verification:** `sudo go test ./test/integration/ -run Smoke_SynTfo -v` passes.

---

## Phase 2 — Security Layer

**Goal:** Add HKDF key derivation, ChaCha20-Poly1305 AEAD, and anti-replay. These are isolated primitives; integration with the wire format is Phase 3.

**Exit criteria:** `cipher: chacha20poly1305` is a valid config option; encrypted payloads round-trip; a replay attempt is rejected.

---

### T2.1 — HKDF-SHA256 key derivation

**Scope:** Given a user-provided PSK (any length), derive two 32-byte keys: `encKey` and `authKey`.

**Files touched:**
- `internal/crypto/keyderive.go` (new)
- `internal/crypto/keyderive_test.go` (new)

**Dependencies:** none (independent — can run parallel to Phase 1)

**DoD:**
- [ ] Uses `golang.org/x/crypto/hkdf` with `sha256.New`.
- [ ] Salt is a 16-byte project constant defined in the same file (commented as "MUST NOT change between versions without bumping the protocol version in HKDF info string").
- [ ] Info string is `"ctun-v1"` (exact bytes), enabling future v2 rollover by changing the suffix.
- [ ] `DeriveKeys(psk []byte) (encKey, authKey [32]byte)` signature exactly as in design §8.1.
- [ ] Test asserts known-answer test vectors for a fixed PSK (record outputs as golden values).
- [ ] Test asserts `encKey != authKey` for any non-trivial PSK.

**Verification:** `go test ./internal/crypto/ -run TestDeriveKeys -v`

---

### T2.2 — ChaCha20-Poly1305 AEAD wrapper

**Scope:** Thin wrapper around `golang.org/x/crypto/chacha20poly1305` providing `Seal(plaintext) → nonce||ciphertext||tag` and the inverse `Open`.

**Files touched:**
- `internal/crypto/aead.go` (new)
- `internal/crypto/aead_test.go` (new)
- `internal/conf/` (extend cipher enum to include `chacha20poly1305`)
- The site in paqet that selects ciphers (the cipher registry — locate during T1.1 walkthrough; usually `internal/protocol/` or a `cipher.go`)

**Dependencies:** T2.1

**DoD:**
- [ ] Nonce is 12 bytes, drawn from `crypto/rand` per call. Reuse is impossible by construction (no nonce parameter exposed to callers).
- [ ] Output layout is exactly `[nonce:12][ciphertext:N][tag:16]`.
- [ ] `Open` returns a typed `ErrAuthFailed` on tag mismatch (not just generic error) so the caller can distinguish from corruption.
- [ ] Selecting `cipher: chacha20poly1305` in the YAML config picks this AEAD; selecting `aes-256-gcm` etc. still works (do not regress paqet's existing ciphers).
- [ ] Tests cover: round trip, tampered ciphertext rejected, tampered tag rejected, wrong key rejected.
- [ ] Benchmark `BenchmarkChaCha20Poly1305_Seal_1KB` recorded in the test output for future regression watching.

**Verification:**
```bash
go test ./internal/crypto/ -run TestAEAD -v
go test -bench=. ./internal/crypto/
```

---

### T2.3 — Anti-replay sliding window

**Scope:** 64-bit sliding window replay filter as specified in design §8.3.

**Files touched:**
- `internal/crypto/antireplay.go` (new)
- `internal/crypto/antireplay_test.go` (new)

**Dependencies:** none (independent)

**DoD:**
- [ ] Implements exactly the `Check(seq uint64) bool` signature from design §8.3.
- [ ] Thread-safe (concurrent `Check` from many goroutines is safe and linearizable).
- [ ] Returns `true` for new in-window sequence numbers; `false` for too-old or duplicate.
- [ ] Window shift on a far-future seq does not panic and correctly resets unrelated bits.
- [ ] Tests cover: in-order, out-of-order within window, exact duplicate, just-too-old, far-future jump, concurrent stress (1000 goroutines × 1000 ops, no race).
- [ ] `go test -race` clean.

**Verification:** `go test -race ./internal/crypto/ -run TestReplay -v`

---

## Phase 3 — Wire Format + Handshake

**Goal:** Replace paqet's `encoding/gob` payload with a fixed binary layout, then implement the HELLO/HELLO_ACK handshake and wire the real `CookieProvider` (replacing T1.2's stub).

**Exit criteria:** A server with a wrong PSK never decrypts anything; replay attempts are dropped; the handshake establishes a session and subsequent packets carry the real HMAC cookie.

---

### T3.1 — Binary wire format (replaces gob)

**Scope:** Replace `internal/protocol/protocol.go`'s gob-based serialization with the fixed-layout binary format in design §13.1.

**Layout (plaintext, before AEAD):**
```
[SessionID:4][Sequence:8][Flags:1][Length:2 BE][Payload:N]
```

**Files touched:**
- `internal/protocol/protocol.go` (rewrite)
- `internal/protocol/protocol_test.go` (new — replace any gob-era tests)
- Call sites that encode/decode protocol messages

**Dependencies:** none structural (independent of Phase 2)

**DoD:**
- [ ] `encoding/gob` no longer imported anywhere.
- [ ] Marshal/Unmarshal are deterministic: identical input → identical bytes.
- [ ] Header is exactly 15 bytes for every message.
- [ ] `Flags` byte uses the bit definitions from design §13.1 (`HELLO=0`, `HELLO_ACK=1`, `DATA=2`, `KEEPALIVE=3`, `CLOSE=4`).
- [ ] Unmarshal rejects truncated input with a typed error.
- [ ] Unmarshal asserts `Length` matches actual remaining bytes; rejects mismatches.
- [ ] Fuzz target `FuzzProtocolUnmarshal` runs ≥ 10 000 iterations in CI without panic.
- [ ] All packet types previously encoded by gob have a binary equivalent (no functional regression).

**Verification:**
```bash
go test ./internal/protocol/ -v
go test -fuzz=FuzzProtocolUnmarshal -fuzztime=30s ./internal/protocol/
```

---

### T3.2 — Session manager + real TFO cookie provider

**Scope:** Implement `internal/session/` providing session IDs and an HMAC-based `CookieProvider` that replaces T1.2's stub. The cookie is `HMAC-SHA256(authKey, sessionID)[0:8]`.

**Files touched:**
- `internal/session/manager.go` (new)
- `internal/session/manager_test.go` (new)
- `internal/transport/syntfo/cookie.go` (wire the real provider here)
- `cmd/server.go`, `cmd/client.go` (construct the manager and pass to transport)

**Dependencies:** T1.2, T1.3, T2.1

**DoD:**
- [ ] Server validates incoming cookies; mismatches drop silently and increment `dropped_bad_cookie` counter.
- [ ] Client uses the session-bound cookie on every post-handshake packet.
- [ ] Pre-handshake packets (HELLO only) use an all-zero cookie; server treats zero cookie as "candidate handshake — try to decrypt as HELLO."
- [ ] Session IDs are 4 random bytes, generated by the server and echoed back in HELLO_ACK.
- [ ] No goroutine leaks (`go test -race` plus a leak check via `goleak`).
- [ ] Tests cover: valid cookie accepted, wrong cookie dropped, zero cookie only accepted for HELLO, session rotation when client reconnects.

**Verification:** `go test ./internal/session/ -race -v`

---

### T3.3 — HELLO / HELLO_ACK handshake

**Scope:** Implement the initial authentication exchange from design §8.4.

**Files touched:**
- `internal/session/handshake.go` (new)
- `internal/session/handshake_test.go` (new)

**Dependencies:** T3.1, T3.2

**DoD:**
- [ ] Client sends `HELLO{version=1, timestamp, hmac=HMAC(authKey, "hello"||timestamp_be8)}`.
- [ ] Server validates HMAC in constant time (`hmac.Equal`).
- [ ] Server rejects timestamps more than ±60 seconds from its clock (replay window for the handshake itself).
- [ ] On accept, server replies `HELLO_ACK{sessionID, hmac=HMAC(authKey, sessionID)}`.
- [ ] On reject, server sends nothing — completely silent, no RST, no error packet.
- [ ] Client retries HELLO up to 5 times with exponential backoff (250 ms → 4 s) before giving up.
- [ ] Test "wrong PSK on client" → handshake fails; server logs exactly one `dropped_handshake_bad_hmac` increment and emits zero packets in response.
- [ ] Test "stale timestamp" → handshake rejected.

**Verification:** `go test ./internal/session/ -run TestHandshake -v`

---

### T3.4 — Wire anti-replay into the receive pipeline

**Scope:** After AEAD `Open` succeeds, extract the `Sequence` field from the decrypted header and call `ReplayFilter.Check`. Drop on `false`.

**Files touched:**
- The post-decrypt path in `internal/transport/syntfo/` or wherever decrypt currently happens (locate during T2.2)
- New unit test exercising the full path: encrypt → tamper sequence → decrypt → assert filter rejects duplicate

**Dependencies:** T2.3, T3.1, T3.2

**DoD:**
- [ ] One `ReplayFilter` per session (not global).
- [ ] Filter is reset when a new session is established.
- [ ] Replayed packet is dropped silently; counter `dropped_replay` incremented.
- [ ] Integration test "client sends N packets, attacker re-injects the first" → server processes N exactly once.

**Verification:** Integration test in `test/integration/replay_test.go` passes.

---

### T3.5 — End-to-end secure tunnel test

**Scope:** A single integration test that exercises the full Phase 1–3 stack: SYN-TFO transport + ChaCha20-Poly1305 + HKDF + anti-replay + handshake.

**Files touched:**
- `test/integration/secure_tunnel_test.go` (new)
- `test/integration/fixtures/server-secure.yaml`, `client-secure.yaml`

**Dependencies:** T3.3, T3.4

**DoD:**
- [ ] Test runs an HTTP round trip with `cipher: chacha20poly1305` and asserts 200.
- [ ] Sub-test "wrong PSK on client": client cannot complete handshake; server emits zero response packets (verified by packet sniff); test asserts a connection-timeout error on the client within a bounded time.
- [ ] Sub-test "tampered ciphertext in flight": uses a packet rewriter on loopback to flip a byte; server drops; client's KCP retransmits; round trip still succeeds eventually.
- [ ] Runs in under 30 s.

**Verification:** `sudo go test ./test/integration/ -run SecureTunnel -v`

---

## Phase 4 — Firewall Automation + Cross-Platform

**Goal:** Replace the manual `iptables` command in paqet's README with automatic apply/cleanup on Linux, macOS, and Windows.

**Exit criteria:** A single `ctun server` invocation installs the right firewall rules at startup and removes them on SIGINT/SIGTERM, on all three OSes. CI builds (and where possible runs) on all three.

---

### T4.1 — `Firewall` interface and Linux implementation

**Scope:** Define the interface and ship the Linux (`iptables`) implementation per design §12.

**Files touched:**
- `internal/firewall/firewall.go` (new — interface)
- `internal/firewall/linux.go` (new, build tag `linux`)
- `internal/firewall/linux_test.go` (new — uses `iptables-save` to verify, requires root)
- `internal/conf/` (add `firewall.auto`, `firewall.backend`)

**Dependencies:** T1.5 (need a working tunnel to test against)

**DoD:**
- [ ] Interface exactly: `type Manager interface { Apply(port uint16, isServer bool) error; Cleanup() error }`.
- [ ] Rules are tagged with comment `ctun-<port>` via `-m comment --comment` so cleanup is exact and safe alongside unrelated rules.
- [ ] `Apply` is idempotent: calling it twice does not duplicate rules.
- [ ] `Cleanup` removes only rules with the `ctun-<port>` comment.
- [ ] A signal handler installed at server/client startup invokes `Cleanup` on SIGINT, SIGTERM, and panic recovery.
- [ ] Integration test (Linux only, gated by `-short=false` and root): start `ctun server`, assert rule present via `iptables -t raw -L -n`, send SIGTERM, assert rule absent.
- [ ] Documentation comment on `Apply` lists every command it runs.

**Verification:** `sudo go test ./internal/firewall/ -run TestLinux -v`

---

### T4.2 — macOS (pf) implementation

**Scope:** macOS counterpart using `pfctl`. Writes a temporary anchor file rather than mutating `/etc/pf.conf` so cleanup is trivial.

**Files touched:**
- `internal/firewall/darwin.go` (new, build tag `darwin`)
- `internal/firewall/darwin_test.go` (new — requires root)

**Dependencies:** T4.1 (interface defined there)

**DoD:**
- [ ] Uses a named anchor `ctun.<port>` loaded with `pfctl -a ctun.<port> -f <tmpfile>`.
- [ ] `Cleanup` flushes the anchor: `pfctl -a ctun.<port> -F all`.
- [ ] Anchor file path goes to `os.TempDir()` and is removed on `Cleanup`.
- [ ] Idempotent `Apply`.
- [ ] Integration test on a macOS CI runner (or skipped with clear reason if no runner is available).

**Verification:** `sudo go test ./internal/firewall/ -run TestDarwin -v` on macOS.

---

### T4.3 — Windows (netsh) implementation

**Scope:** Windows counterpart using `netsh advfirewall`.

**Files touched:**
- `internal/firewall/windows.go` (new, build tag `windows`)
- `internal/firewall/windows_test.go` (new — requires admin)

**Dependencies:** T4.1

**DoD:**
- [ ] Rule name format `ctun-<port>` so cleanup is exact.
- [ ] `Apply` issues `netsh advfirewall firewall add rule ...` with `dir=in action=block protocol=TCP localport=<port>`.
- [ ] `Cleanup` issues `netsh advfirewall firewall delete rule name=ctun-<port>`.
- [ ] Idempotent (rule existence checked before add).
- [ ] Integration test on a Windows CI runner.

**Verification:** Windows CI job runs the test.

---

### T4.4 — Signal-handler-driven cleanup wiring

**Scope:** Make sure `Cleanup` is called in every shutdown path: SIGINT, SIGTERM, panic, fatal log. Single source of truth — no per-platform duplication.

**Files touched:**
- `cmd/server.go`, `cmd/client.go` (wire `signal.Notify` + `defer mgr.Cleanup()`)
- `internal/firewall/firewall.go` (export a helper `InstallCleanup(ctx, mgr)` if it simplifies)

**Dependencies:** T4.1, T4.2, T4.3

**DoD:**
- [ ] Killing the process with `kill -9` is acknowledged as a known gap (cannot intercept SIGKILL) and documented in the README troubleshooting section, with a manual cleanup recipe per OS.
- [ ] For all other exit paths (clean exit, SIGINT, SIGTERM, panic), an integration test confirms rule removal.
- [ ] `defer mgr.Cleanup()` chain runs even if `Apply` partially succeeded (cleanup tolerates "rule not present").

**Verification:** Manual test on each OS plus integration tests added in T4.1–T4.3.

---

### T4.5 — Cross-platform CI matrix

**Scope:** Extend the CI workflow to build (and run unit tests for) Linux amd64/arm64, macOS amd64/arm64, Windows amd64. Integration tests stay on Linux only for cost reasons (documented).

**Files touched:**
- `.github/workflows/build.yml`

**Dependencies:** T4.1, T4.2, T4.3

**DoD:**
- [ ] CI green on all five `(os, arch)` targets for `go build`.
- [ ] CI green on `go test ./...` (unit tests, no integration) for Linux, macOS, Windows.
- [ ] CI green on `sudo go test ./test/integration/` for Linux only.
- [ ] Release job uploads checksummed artifacts for all five targets.
- [ ] libpcap/Npcap install steps documented in the workflow with comments.

**Verification:** A green PR build and a green tagged release.

---

### T4.6 — Cleanup: remove paqet baseline tests, refresh README

**Scope:** Drop the `t.Skip`'d baseline test from T0.2/T0.3, rewrite the README to describe ctun (not the inherited paqet one), document required capabilities and firewall behavior.

**Files touched:**
- `test/integration/smoke_paqet_baseline_test.go` (delete)
- `test/integration/smoke_syn_only_test.go` (delete; superseded by T1.5)
- `README.md` (replace stub from T0.1 with full doc: install, run, config, troubleshooting)
- `docs/findings/T0.3-syn-only-feasibility.md` (delete; historical only)

**Dependencies:** T4.5

**DoD:**
- [ ] README has sections: Install, Quick start (client + server one-liners), Configuration, Firewall behavior, Troubleshooting, License & attribution.
- [ ] README explicitly credits paqet upstream.
- [ ] `go test ./...` and integration tests still green after deletions.
- [ ] `ctun --help` output matches what the README documents.

**Verification:** PR review — no automated check beyond CI staying green.

---

### T4.7 — CI fixups: arm64 apt sources + integration-test server readiness

**Scope:** Two T4.5 follow-ups surfaced by the first real CI run. Neither was caught locally because (a) cross-compile arm64 was never actually exercised on a noble runner and (b) the sudo-gated integration tests were never run on Linux.

1. **arm64 build apt sources** — `dpkg --add-architecture arm64` followed by `apt-get update` fails because the runner's default apt sources (in `/etc/apt/sources.list.d/ubuntu.sources`, deb822 format on noble) are not restricted to amd64, so apt asks `security.ubuntu.com` for arm64 packages and 404s. The existing `sed` against `/etc/apt/sources.list` is a no-op on noble. Workflow also pins the added arm64 list to `jammy` while the runner is `noble`.
2. **integration-test server readiness** — All sudo-gated tests time out at `waitFor("server listening on :<port>")`. The probe is `tcpPortListening` (TCP dial), but the SYN-TFO server has no kernel TCP listener on the tunnel port — only pcap send/recv handles. `tcpPortListening` for the server can never return true. The fixture `log.level: "warn"` also silences the actual "Server started — listening for packets on :PORT" line, so the failure diagnostic shows empty subprocess output.

**Files touched:**
- `.github/workflows/build.yml` (arm64 apt setup; pin to runner distro)
- `test/integration/helpers_test.go` (add log-substring readiness helper)
- `test/integration/smoke_syn_tfo_test.go`, `secure_tunnel_test.go` (server wait → log substring)
- `test/integration/fixtures/server-syntfo.yaml`, `server-secure.yaml` (raise `log.level` so readiness line is emitted)

**Dependencies:** T4.5

**DoD:**
- [ ] arm64 build job green on a hosted ubuntu-latest runner.
- [ ] integration-tests job green on a hosted ubuntu-latest runner (root via `sudo -E`).
- [ ] `tcpPortListening` is still used for the client (which DOES bind a real SOCKS5 net.Listen).
- [ ] On failure, subprocess output includes the server's startup log so future regressions are diagnosable.

**Verification:** Green CI on push to main.

---

### T4.8 — CI fixups: loopback SrcMAC normalisation + serialize-error diagnostics

**Scope:** Second-round T4.5 follow-up surfaced once T4.7 unblocked the readiness probe and the sudo-gated integration tests started executing on the hosted ubuntu-latest runner. With the server reachable and SOCKS5 listening, every test still failed with `Get http://...: EOF` and the silent-PSK test's own diagnostic reported "observed 0 client→server SYNs" — impossible if the pcap inject path was working.

Repro inside an `ubuntu:24.04` container (`--cap-add=NET_RAW NET_ADMIN`, Go 1.25, libpcap-dev, iptables) confirmed:

1. **Empty `lo.HardwareAddr` on Linux.** `net.InterfaceByName("lo").HardwareAddr` returns a nil/zero-length slice on noble (and every other distro tested). The Ethernet pool in `internal/socket/send_handle.go:NewSendHandle` captures that empty value into `layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr}`. `gopacket.layers.Ethernet.SerializeTo` rejects any `SrcMAC` whose length is not 6 with the literal error `"invalid src MAC: "` (verified at `gopacket@v1.5.0/layers/ethernet.go:69-73`). `gopacket.SerializeLayers` therefore fails on every outbound packet, the error propagates up through `PacketConn.WriteTo`, and KCP swallows it silently inside its update goroutine. End state: zero packets on the wire, no diagnostic anywhere.
2. **Pcap LinkType on `lo` is `Ethernet` (DLT_EN10MB)** on noble — verified with a one-shot Go probe against an open pcap handle. The hardcoded `layers.LayerTypeEthernet` in `internal/socket/recv_handle.go:Read` is the correct initial decoder, so no recv-side change is needed beyond a verification comment noting the platforms we've checked.

**Files touched:**
- `internal/socket/send_handle.go` (normalise empty `Interface.HardwareAddr` to `net.HardwareAddr{0,0,0,0,0,0}`; add `writeSerializeErr` / `writePcapErr` atomic counters and a one-shot warn-level log per failure mode so silent KCP-swallowed errors surface in operator/CI logs without per-packet spam)
- `internal/socket/recv_handle.go` (comment documenting that `LayerTypeEthernet` is correct on every supported platform; no behaviour change)
- `docs/implementation-doc.md` (this entry)

**Dependencies:** T4.5, T4.7

**DoD:**
- [ ] `net.HardwareAddr` of length != 6 on the configured interface is normalised to six zero bytes; a real MAC on non-loopback interfaces is preserved unchanged.
- [ ] `gopacket.SerializeLayers` failures bump `writeSerializeErr` and emit exactly one `flog.Warnf` per `SendHandle` lifetime (subsequent failures are counter-only).
- [ ] `pcap.WritePacketData` failures bump `writePcapErr` and emit exactly one `flog.Warnf` per `SendHandle` lifetime.
- [ ] `recv_handle.go` carries an inline note recording the platforms on which `LinkType` was verified to equal Ethernet, so a future regression on a non-Ethernet link surface is debuggable from the source alone.
- [ ] `Test_SecureTunnel_WrongPSK_HandshakeFails`, `Test_SecureTunnel_TamperedCiphertext_DropAndRecover`, and `Test_AntiReplay_ClientSendsN_AttackerReinjectsFirst` (the in-memory tests that were already green) still pass — no regression.

**Verification:**
- `go vet ./...`, `gofmt -l .`, `go build ./...`, `go test -race -short ./...` clean on the macOS host.
- Repro container (`ubuntu:24.04 + NET_RAW/NET_ADMIN + libpcap-dev + iptables + Go 1.25`) confirms the SerializeLayers error is gone on a loopback interface with an empty HardwareAddr.

**Known follow-up (separate task, escalated to coordinator):** the sudo-gated `Test_Smoke_SynTfo` and `Test_SecureTunnel` round-trip tests do not pass after this fix alone. Root cause is independent of T4.8: production `cmd/run/{client,server}.go` never invokes `session.RunClientHandshake` / `session.RunServerHandshake` (and never installs a `HelloHandler` on the syntfo transport), so `syntfo.secureConn.WriteTo` returns `ErrNoSession` on the first KCP segment and the tunnel never carries data. T3.3 shipped the handshake primitives; the production-time driver was never wired. This is the next item to address; T4.8's scope is bounded to the pcap-layer EOF described above. **Closed in T4.9.**

---

### T4.9 — Wire production handshake driver + pcap-poll timeout

**Scope:** Close T4.8's flagged follow-up. T3.3 and T3.5 ticked DoD items for HELLO/HELLO_ACK wiring and the secure-tunnel round trip without ever exercising them on Linux; production startup neither drove `session.RunClientHandshake` on the client nor installed a `HelloHandler` on the server, and the server-side per-addr session map that `secureConn.WriteTo` is documented to consult was never built. After this task all six sudo-gated round-trip / silent-PSK paths pass under the Docker repro environment (`ubuntu:24.04` + `NET_RAW/NET_ADMIN` + `libpcap-dev` + `iptables` + Go 1.25).

Two protocol decisions worth recording, both made in this task:

1. **HELLO_ACK carries cookie=zero on the wire** — symmetric with HELLO. The client manager hasn't bound the new session at HELLO_ACK arrival time, so any non-zero cookie would either need a "pending handshake" pass-through in the gate or a synthetic LookupByCookie against a session the client has never registered. Going with cookie=zero adds one switch arm to `gateOptions` (FlagHello → handler, FlagHelloAck → upper layer) and keeps the cookie validator's invariants intact.
2. **Client RecvHelloAck reads PacketConn directly, in the same goroutine as the session-layer retry loop**, rather than waiting on a "pump" goroutine that stashes HELLO_ACKs into a channel. With pcap reads now bounded by a poll timeout (see below), the same goroutine can sleep on a read deadline and be unblocked by ctx cancellation — the inversion the file header explains.

The deeper bug T4.8 surfaced — pcap's `SetTimeout(pcap.BlockForever)` — also lands here because the production handshake driver is the first caller that actually needed deadline / ctx responsiveness on a quiet recv. Pre-T4.9, `socket.PacketConn.ReadFrom`'s deadline / ctx check was a one-shot: once `pcap.ReadPacketData` was in flight, only an arriving packet (or handle close) could release it. Wrong-PSK never produced an arriving packet, so the client handshake's 9 s ctx fired but couldn't interrupt the read, and `RunClientHandshake` never returned. Server-side SIGTERM had the same shape — the recv loop was blocked in pcap and ignored ctx cancel.

Fix: `internal/socket/handle.go` sets `SetTimeout(250 ms)`; `internal/socket/socket.go ReadFrom` loops over `pcap.NextErrorTimeoutExpired` returns and re-checks ctx / deadline between iterations. The on-the-wire semantics are unchanged (caller still blocks until a real event); the only behavioural change is that ctx cancellation and read deadlines are now observable within ~250 ms.

The clients' local pcap-recv port was also pinned (fixtures `client-syntfo.yaml`, `client-secure.yaml`): the pre-T4.9 `127.0.0.1:0` expanded to BPF `dst port 0`, which dropped every inbound packet from the server. Tests allocate a fresh free loopback port via `allocClientLoopbackPort` and pass it through the new `fixtureParams.ClientPort` field. The mangle/OUTPUT DROP-RST firewall rule, previously server-only, is now installed on both sides because pinning a real client port surfaces the kernel-RST race on inbound HELLO_ACK that the pre-T4.9 zero port masked.

**Files touched:**
- `internal/transport/syntfo/handshake.go` (new — `clientHandshakeSender`, `serverHandshakeSender`, `Transport.RunClientHandshake`, `Transport.InstallServerHandshakeHandler`)
- `internal/transport/syntfo/syntfo.go` (extend gate to dispatch FlagHello vs FlagHelloAck; thread dst addr through the SYN options builder so the server can stamp the per-destination session's cookie)
- `internal/transport/syntfo/secure_conn.go` (server-side fallback to per-addr session map in `WriteTo` when binding is unbound)
- `internal/transport/syntfo/{gate_handshake,recv}_test.go` (signature updates for the widened gate)
- `internal/socket/{handle,socket,send_handle,recv_handle}.go` (pcap poll timeout + ReadFrom loop; dst addr plumbed into SYNOptionsBuilder; src addr plumbed into SYNGate so the HELLO handler gets a real peer)
- `internal/session/manager.go` (`AuthKey()` accessor so the production driver can derive the HMAC key the manager was built with)
- `internal/client/{client,dial,timed_conn}.go` (drive `Transport.RunClientHandshake` between `transport.New` and `kcp.Dial`; handshake failures no longer abort `Client.Start` so SOCKS5 still binds; `ErrNoTunnelConn` surfaced for downstream dials)
- `internal/server/server.go` (install the per-Transport HELLO handler before `kcp.Listen`)
- `cmd/run/firewall_setup.go`, `internal/firewall/firewall.go`, `firewall_test.go` (DROP-RST rule installed on both sides; `firewallPort` uses the client's local pcap-recv port on the client side)
- `test/integration/fixtures/client-{syntfo,secure}.yaml` (pin client port via `{{.ClientPort}}`; bump log level to `info` so subprocess log carries handshake-complete diagnostics)
- `test/integration/{helpers_test,secure_tunnel_test,smoke_syn_tfo_test}.go` (allocate the client port, plumb it through `fixtureParams`, extend the wrong-PSK SOCKS5 wait to 15 s to absorb the handshake-budget worst case)

**Dependencies:** T3.3, T3.5, T4.5, T4.7, T4.8

**DoD:**
- [x] `Transport.RunClientHandshake(ctx, peer, authKey)` returns the bound `*session.Session` on success and `ErrHandshakeTimeout` / `context.DeadlineExceeded` on failure.
- [x] `Transport.InstallServerHandshakeHandler(ctx, authKey)` installs a handler that drives `session.RunServerHandshake` per inbound HELLO and writes the resulting session into the secureConn's per-addr map.
- [x] HELLO and HELLO_ACK both ride on the wire with cookie=zero; the gate dispatches HELLO to the handler (drop-from-KCP) and HELLO_ACK to the upper layer (accept).
- [x] Server-side `secureConn.WriteTo` looks up the destination's session in the per-addr map; never returns `ErrNoSession` for an addr the recv path has already accepted an AEAD frame from.
- [x] Client-side `secureConn.WriteTo` continues to return `ErrNoSession` when called before the handshake completes (no silent plaintext downgrade).
- [x] `pcap.ReadPacketData` no longer blocks longer than the configured poll timeout; ctx cancellation and read deadlines are observable within that window.
- [x] All six sudo-gated round-trip / silent-PSK tests pass in the Docker repro: `Test_SecureTunnel` (both subtests), `Test_Smoke_SynTfo` (both subtests), `Test_SecureTunnel_WrongPSK_ServerSilent`, `Test_AntiReplay_ClientSendsN_AttackerReinjectsFirst`.
- [x] In-memory tests still pass: `Test_SecureTunnel_WrongPSK_HandshakeFails`, `Test_SecureTunnel_TamperedCiphertext_DropAndRecover`.
- [x] `go vet ./...`, `gofmt -l .`, `go build ./...`, `go test -count=1 -race -short ./...` clean on the macOS host.

**Verification:**
- `docker exec ctun-repro go test -count=1 -v ./test/integration/` returns PASS for every test listed under DoD. All six sudo-gated tests complete in under 14 s wall time total (vs. timing out indefinitely on `main`).
- On a successful round trip the subprocess log carries `Server started — listening for packets on :PORT` and `client handshake complete: session bound (id=…)` — the readiness probes T4.7 introduced still work.

**Open follow-ups (not in scope):**
- Session-table GC on the server (sessions accumulate per inbound HELLO; the manager has no eviction policy yet). Track under the existing manager.go TODO.
- Metrics scraper that exposes the syntfo + session counters. Existing follow-up under Cross-Cutting Concerns / Metrics.
- The SOCKS5 binding being synchronous w.r.t. the handshake is a deliberate trade-off: connection-time backpressure beats accepting clients before the tunnel can carry traffic. If a future deployment wants async binding, that's a separate Phase-7+ refactor; the SOCKS5 wait in the wrong-PSK test absorbs the worst-case 9 s budget.

---

## Phase 5 — Optional: No-CGO Backend (Future)

**Goal:** Add an AF_PACKET (Linux) and `/dev/bpf` (macOS) backend behind a build tag so users who care about static binaries can opt out of libpcap.

**Status:** Future. Not part of MVP. Listed for completeness so the project structure leaves room.

- **T5.1** AF_PACKET socket implementation matching `Transport` interface, build tag `!cgo,linux`.
- **T5.2** `/dev/bpf` implementation, build tag `!cgo,darwin`.
- **T5.3** Second CI matrix lane with `CGO_ENABLED=0` building only Linux + macOS, no Windows.
- **T5.4** Documentation: when to choose which backend.

DoD and verification for each task to be detailed when Phase 5 is scheduled.

---

## Phase 6 — Additional Transports (Future)

- **T6.1** SYN-ACK transport (server initiates the unsolicited SYN-ACK pattern).
- **T6.2** UDP transport (for benchmark comparison and as a fallback when middleboxes block SYN-payload).
- **T6.3** Raw IP transport (protocol field experiment).

Each must implement the `Transport` interface unchanged; if any can't, that is a finding to revisit the interface — file a design-doc revision before coding.

---

## Cross-Cutting Concerns (apply to every task)

### Logging

- Use `internal/flog/` (paqet's logger). Do not introduce a second logging library.
- Hot-path code (per-packet) logs at `debug` only; counters preferred over log lines.

### Metrics

- A simple `expvar` or `prometheus`-style counter is acceptable; pick one in Phase 1 (file a follow-up if undecided) and use consistently.
- Required counters introduced by these tasks: `dropped_no_tfo`, `dropped_bad_cookie`, `dropped_handshake_bad_hmac`, `dropped_replay`, `dropped_aead_open_fail`.

### Errors

- Use typed errors (`var ErrXxx = errors.New(...)`) for conditions callers may branch on (`ErrAuthFailed`, `ErrReplay`, `ErrUnknownTransport`).
- Wrap with `fmt.Errorf("...: %w", err)` to preserve causes.

### Testing requirements

- Every new package ships with `_test.go` covering happy path and the explicit error paths.
- `go test -race ./...` clean on every PR.
- Integration tests gated on `-short=false` and root/admin so `go test ./...` works for non-privileged contributors.

### Definition of "Reviewable PR"

- One task = one PR, named `ctun/T<id>-<slug>`.
- PR description copies the task DoD with ticked boxes.
- Reviewer rejects if a DoD box is unchecked without justification.

---

## Appendix A — Task Dependency Graph

```
T0.1 ─→ T0.2 ─→ T0.3 ─→ T1.1 ─→ T1.2 ─→ T1.3 ─→ T1.5
                            └─→ T1.4 ─────────────┘
                                                  │
T2.1 ─→ T2.2                                      │
T2.3 ──┐                                          │
       └─→ T3.4                                   │
T3.1 ──┴─→ T3.2 ─→ T3.3 ─→ T3.5 ←────────────────┘
                                  │
                                  └─→ T4.1 ─→ T4.2
                                       │   └─→ T4.3
                                       └─→ T4.4 ─→ T4.5 ─→ T4.6
```

Phase 2 tasks (T2.1, T2.2, T2.3) can begin in parallel with Phase 1 since they touch unrelated packages.

---

## Appendix B — Estimated effort

| Phase | Tasks | Estimate | Critical path |
|-------|-------|----------|---------------|
| 0 | T0.1–T0.3 | 2 days | T0.1 → T0.2 → T0.3 |
| 1 | T1.1–T1.5 | 5–7 days | T1.1 → T1.2 → T1.3 → T1.5 |
| 2 | T2.1–T2.3 | 3–4 days (parallel with Phase 1) | T2.1 → T2.2 |
| 3 | T3.1–T3.5 | 5–7 days | T3.1 → T3.2 → T3.3 → T3.5 |
| 4 | T4.1–T4.6 | 5–7 days | T4.1 → T4.4 → T4.5 → T4.6 |
| **Total MVP** | | **~4 weeks** | |
| 5–6 | future | TBD | |

Estimates assume one engineer familiar with Go networking. Adjust on review.

---

## Appendix C — Follow-ups discovered during implementation

Items intentionally deferred from a task's original DoD, with reason. Pick these up in the noted phase.

### From T0.1

- **GitHub `<owner>/ctun` repo creation** — N/A under the current coordinator policy (no remotes, no pushing). Re-evaluate when the project moves to a hosted repo. The `upstream` remote *is* configured locally so future `git fetch upstream` works.
- **`server` / `client` subcommands in `--help`** — Upstream paqet exposes a single config-driven `run` subcommand instead of separate `server`/`client`. The T0.1 DoD's enumeration was aspirational. Splitting `run` into two subcommands is a UX refactor and should be filed as its own task in Phase 4 if we still want it; current docs in design-doc.md describe `ctun server`/`ctun client` invocations, so this divergence will need reconciling either in code (split the command) or in the design doc (document `ctun run` instead). T4.6 documented `ctun run` in the README to match the binary; the design-doc reconciliation is still open.
- **`internal/conf/kcp_block.go` PBKDF2 salt `"paqet"`** — Deliberately preserved because it is a wire-protocol constant; T2.1 replaces the whole derivation with HKDF, which retires this string organically.

### From T0.2

- **Local sudo-gated verification on macOS** — Not run on this developer box; no cached `sudo` and the CLI harness can't enter a password. The test is written, compiles, and skips cleanly without root. Verification is deferred to a Linux CI runner (T4.5) or a manual `sudo go test ./test/integration/ -run Smoke_PaqetBaseline -v` invocation by the developer.
- **Loopback link-layer framing** — `internal/socket/send_handle.go` always emits an Ethernet frame via gopacket, using `cfg.Interface.HardwareAddr` for SrcMAC and `cfg.IPv4.Router` for DstMAC. On macOS `lo0` (link-type DLT_NULL, no Ethernet header, no MAC) this almost certainly won't inject. On Linux `lo` the synthetic Ethernet header probably accepts the all-zero MAC. **Decision needed before integration tests can run on macOS locally**: either (a) teach the SYN-TFO transport (Phase 1) to handle DLT_NULL by stripping/skipping the Ethernet layer, (b) make all integration testing Linux-only (Docker on macOS or remote CI), or (c) add a "loopback shim" build mode. Option (a) is the cleanest and naturally folds into T1.1's Transport refactor — recommend filing this as a tracked sub-item there if we want the Phase-0 baseline to ever run on macOS. Option (b) is the cheapest and matches the DoD's mention of "two Docker containers with a veth pair on Linux" as an acceptable alternative.

### From T1.1

- **`transport.Config` shape diverges from design-doc §7.1.** Design sketches `Config { Interface, LocalAddr, RemoteAddr, MTU, ExtraParams }`; implementation uses `Config { Ctx, Network *conf.Network, ExtraParams }`. The `Transport` interface itself (`Send`/`Recv`/`LocalAddr`/`Close`) matches design exactly. Rationale: `conf.Network` already carries every atomic field the design lists plus the pcap-specific fields paqet's existing factories need; an atomic-field Config would require a translation layer at every construction site for no gain in Phase 1. **Cost**: `Transport` now has a one-way dependency on `conf.Network`. A future transport that doesn't want the full Network config (e.g. an in-process loopback shim, or a UDP transport per T6.2) will need either to ignore most of Network or to refactor Config into an interface-based shape. Sync the design doc in T4.6.
- **`transport.PacketConnProvider` capability interface** (not in design §7.1). Optional `PacketConn() net.PacketConn` exposed by transports that have a `net.PacketConn` underneath; KCP consumes it. Added because the abstract Transport's Send/Recv shape isn't a drop-in for KCP's `net.PacketConn` consumer. Phase 1+ should migrate KCP-or-replacement to `Send`/`Recv` so this capability can be retired; until then it's a documented escape hatch. Add to design doc in T4.6.
- **`Transport.Recv` allocates a 65535-byte buffer per call** in the syntfo adapter (`internal/transport/syntfo/syntfo.go` Recv). T1.3 owns moving this to a pooled-buffer hot path with zero allocations per accepted packet.
- **`internal/socket/` not physically moved under `internal/transport/syntfo/`** — subagent chose adapter-style (option b in the T1.1 brief) because KCP needs `net.PacketConn` either way and moving the package would have doubled the churn for no semantic benefit. The DoD's "PacketConn is gone OR a thin internal helper to the SYN-TFO transport, not referenced from outside its package" item is still satisfied: `grep` confirms only `syntfo` imports `ctun/internal/socket`. Physical relocation can happen later if it ever pays off; not blocking.
- **`SetClientTCPF` is syntfo-specific, not on the interface.** Server code keeps a concrete `*syntfo.Transport` reference alongside the abstract `transport.Transport` to call it. Other transports that don't carry per-client TCP-flag iterators won't need this; the server's `handle.go` nil-checks before dispatching. Reasonable; document in design doc that "per-client flag plumbing" is a syntfo-only capability.
- **`Names()` uses an inline insertion sort** instead of `sort.Strings`. Minor cleanup the next code-quality pass (run `/simplify`) can fold in.

### From T1.2

- **`internal/socket/send_handle.go` retains a pre-T1.2 legacy fallback** for the SYN option list and seq derivation, gated on `h.synOptionsBuilder == nil`. Reason: syntfo's `socket -> syntfo` import direction forced a `func`-typed hook (cycle break) instead of a direct import; the fallback keeps `socket.SendHandle` usable from tests or future non-syntfo callers that don't install the hook. Today no production path hits the fallback (syntfo always installs both hooks). If a future caller does hit it, they'd silently re-acquire the seq-entropy bug. Two options when this becomes real: (a) remove the fallback and require callers to install the hook, (b) flip the default formula to the entropy-correct version. Pick when a non-syntfo consumer of `socket.PacketConn` actually materialises.
- **`syntfo.MSSValue` is an exported `[]byte` var**, not a const, because `layers.TCPOption.OptionData` requires `[]byte`. Mutation by callers would corrupt every subsequent SYN. Low risk today (no caller mutates it), but the right hardening is either to make it private or to clone-on-read. Defer to a simplification pass.
- **Design-doc §13.2 talks about extending `send_handle.go` directly**; implementation extracted the option-builder into `internal/transport/syntfo/send.go` for testability. On-the-wire content matches design exactly. Sync the design doc in T4.6.

### From T3.1

- **Outer Flags model meets paqet's smux PType model via a sub-type byte.** Design-doc §13.1's 5-flag set describes outer-frame envelopes (HELLO/HELLO_ACK/DATA/KEEPALIVE/CLOSE); paqet's existing `Proto`/`PType` messages (PPING/PPONG/PTCPF/PTCP/PUDP) are stream-level control messages, semantically a layer below. Subagent mapped PPING/PPONG → `FlagKeepalive` and PTCPF/PTCP/PUDP → `FlagData` with a per-message **sub-type byte** at the head of `Payload`. This preserves all existing call sites (no churn in server/client dispatch) and meets the DoD's "no gob, no functional regression" requirement, but it means **the new wire is not the pure 5-flag model the design doc implied** — every `FlagData` frame still carries a paqet-PType byte. Phase 3.2+ will need to decide: (a) keep the sub-type byte as a stable legacy framing detail (low risk; some semantic mud) or (b) split PTCPF/PTCP/PUDP into their own outer flags (cleaner; bigger change). Sync the design doc once that decision lands.
- **`SessionID` and `Sequence` are zero placeholders today** — T3.2 populates `SessionID`, T3.4 populates `Sequence`. Header has space reserved.
- **`internal/protocol/stream.go` ships shim methods (`Proto.Read`/`Proto.Write`)** with the same signature paqet's gob version had, so the eight call sites in `internal/server/`, `internal/client/`, and `internal/tnet/kcp/` migrated with zero diff. If a future refactor wants to retire the `Proto` type entirely, those call sites are the migration surface.

### From T3.4

- **AEAD wrapping of DATA frames was implicitly required by T3.4** but never named as an explicit deliverable in any prior task's DoD. T3.4 ended up owning both AEAD-on-DATA and anti-replay together. The implementation doc's task descriptions assume AEAD is already wired by the time T3.4 lands; this gap should be reconciled when the doc is refreshed.
- **`secureConn` uses a flag-driven fallback for plaintext HELLO** (try AEAD `Open` first; on failure, plaintext `Unmarshal` and accept only if `Flags ∈ {FlagHello, FlagHelloAck}`). The brief recommended pure cookie-driven dispatch, but cookie isn't visible at the `net.PacketConn` boundary — it would have required threading the cookie out of the gate via a sideband channel. The fallback is contained, low-false-positive (random ciphertext parses as a valid handshake-flagged frame with ~2⁻³⁰ probability), and gated upstream by the cookie-driven fast reject. Verify the false-positive math during a future security review; if a sideband channel is acceptable, the cookie-driven dispatch is the cleaner final form.
- **Gate semantics changed from T3.3.** T3.3's gate did `protocol.Unmarshal` on the non-zero-cookie path to validate the cookie against the SessionID. With AEAD-wrapped data frames the inner payload is ciphertext, so that Unmarshal always fails. T3.4 switched the gate to `mgr.LookupByCookie(cookie)` (a new `Manager.LookupByCookie` + `byCookie` map) for the pre-decrypt fast reject; frame-shape validation moved to `secureConn` post-decrypt. Two T3.3 tests asserting `DroppedMalformedFrame` on the non-zero-cookie path were rewritten to assert `DroppedBadCookieValidator` instead.
- **`Manager.ValidateCookie` is unused on the hot path** — `LookupByCookie` superseded it. Tests still call `ValidateCookie`. Either deprecate or merge into `LookupByCookie` in a code-quality pass.
- **Server-side `secureConn.WriteTo` returns `ErrNoSession` today.** Server doesn't maintain a single "bound session" (it handles many concurrent clients), so the secureConn binding is nil on the server side. T3.5 must wire per-destination session lookup before server→client traffic flows. Tracked as a T3.5 prereq.
- **`secureConn.ReadFrom` allocates a 65535-byte scratch buffer per call** — inherits the T1.1 Appendix C allocation note. Same pooled-buffer follow-up.
- **Sequence counter starts at 0; `NextSeq()` returns 1 on first call.** Seq 0 reserved for HELLO/HELLO_ACK plaintext frames. Documented inline.
