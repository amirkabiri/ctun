// Package firewall installs and removes the host-firewall rules ctun needs
// to function. ctun crafts raw TCP packets via libpcap and injects them with
// fabricated sequence numbers and flags; without the rules installed here,
// the host kernel will see those packets as belonging to a connection it
// never opened, and will respond with TCP RST (or, on the server, swallow
// the SYN and answer with SYN-ACK / RST). Either outcome breaks the tunnel.
//
// The rules differ slightly per platform:
//
//   - Linux  (iptables): NOTRACK in raw/PREROUTING & raw/OUTPUT so conntrack
//     ignores the synthetic flow; mangle/OUTPUT drops
//     outbound RSTs on the tunnel port (server-only).
//   - macOS  (pf):       a named anchor `ctun.<port>` loaded with `pfctl -f`;
//     server-side anchor `block drop`s tunnel-port traffic
//     so the kernel cannot emit interfering responses.
//   - Windows (netsh):   installed by T4.3 — stubbed in this task.
//
// The interface and the cleanup helper live in this file so callers compile
// on every OS; the per-OS implementation is selected by build tags.
package firewall

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

// Manager applies and removes the host-firewall rules ctun needs to function.
// ctun crafts raw packets via pcap; without the rules below, the host kernel
// will RST or otherwise interfere with the synthetic traffic.
//
// All implementations MUST tag their rules with a per-port identifier (today
// the comment string "ctun-<port>") so Cleanup can be exact: ctun never
// removes rules it did not install, even if a previous ctun instance crashed
// without cleaning up and left stale rules behind.
type Manager interface {
	// Apply installs the rules for port. isServer selects the server-side
	// rule set vs the client-side rule set (the two differ slightly: server
	// also drops outbound RSTs on the tunnel port). Apply is idempotent —
	// calling twice does not duplicate rules.
	Apply(port uint16, isServer bool) error

	// Cleanup removes only the rules previously installed by this Manager
	// (identified by the tag the implementation embeds in each rule).
	// Tolerates "rule already absent" — Cleanup is safe to call from a
	// panic-recovery path.
	Cleanup() error
}

// ErrNotImplemented is returned by stub implementations on platforms that
// do not yet have a real firewall backend (today: macOS and Windows; T4.2
// and T4.3 will replace those stubs with real implementations).
//
// Callers may branch on this with `errors.Is(err, ErrNotImplemented)` to
// decide whether to fall back to a manual-rules instruction message vs.
// treating the error as fatal.
var ErrNotImplemented = errors.New("firewall: not implemented on this OS")

// InstallCleanup wires Cleanup to SIGINT, SIGTERM, and ctx cancellation.
// It returns an unhook function the caller should defer; calling the unhook
// stops the goroutine and detaches the signal handler so normal shutdown
// paths (where the caller already invokes Cleanup themselves) do not race
// with the signal handler.
//
// T4.4 is the task that wires this into cmd/run/{server,client}.go; this
// helper is provided in T4.1 so the wiring shape is locked in before that
// task lands. Today no production caller invokes InstallCleanup.
//
// The handler is intentionally non-blocking on the slow path: it fires
// Cleanup in a goroutine so a slow `iptables -D` cannot stall signal
// delivery (e.g. if the user is hammering Ctrl-C). The goroutine logs
// the Cleanup error via the returned error — callers wanting visibility
// into Cleanup failure should arrange their own observation, since the
// helper here cannot import the project logger without a dependency cycle
// once cmd/ uses it.
func InstallCleanup(ctx context.Context, mgr Manager) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)
		select {
		case <-sigCh:
			_ = mgr.Cleanup()
		case <-ctx.Done():
			_ = mgr.Cleanup()
		}
	}()

	return func() {
		signal.Stop(sigCh)
		// Closing sigCh would race with the goroutine's select; instead,
		// let the goroutine exit naturally when ctx is cancelled. The
		// caller is expected to cancel ctx before invoking the unhook.
		// We do not block waiting for doneCh here — the goroutine may
		// already have fired Cleanup, or may exit shortly after ctx
		// cancellation propagates.
		_ = doneCh
	}
}

// commentTag returns the per-port cleanup tag embedded in every rule the
// Linux backend installs (and the same string T4.2/T4.3 will use for their
// pf anchor names / netsh rule names). Centralising it here means the
// install path and the cleanup path cannot drift.
func commentTag(port uint16) string {
	return "ctun-" + strconv.FormatUint(uint64(port), 10)
}

// buildApplyArgs returns the iptables argv for each rule Apply needs to
// install on Linux, in install order. It does NOT execute anything — the
// function is pure argv construction so it can be unit-tested on any
// platform (the Linux backend's exec calls are tested separately, root-gated,
// in linux_test.go).
//
// Lives in firewall.go (no build tag) precisely so macOS developers can
// validate the rule shape without a Linux runner. The returned slices are
// full argv vectors for `iptables` (i.e. element 0 of the eventual exec
// argv array is "iptables", elided here). Each slice contains exactly one
// "-A" token so callers can swap the action verb via swapAction.
//
// The three rules emitted are documented in detail above linux.go's
// linuxManager type.
func buildApplyArgs(port uint16, isServer bool) [][]string {
	tag := commentTag(port)
	portStr := strconv.FormatUint(uint64(port), 10)

	rules := [][]string{
		// raw/PREROUTING NOTRACK on --dport: tell conntrack to ignore
		// incoming SYNs to the tunnel port so the kernel doesn't try to
		// promote them into established connections.
		{
			"-t", "raw",
			"-A", "PREROUTING",
			"-p", "tcp",
			"--dport", portStr,
			"-m", "comment", "--comment", tag,
			"-j", "NOTRACK",
		},
		// raw/OUTPUT NOTRACK on --sport: tell conntrack to ignore packets
		// we craft and inject with --sport=<tunnel-port>, so the kernel
		// won't generate a "connection unknown" response.
		{
			"-t", "raw",
			"-A", "OUTPUT",
			"-p", "tcp",
			"--sport", portStr,
			"-m", "comment", "--comment", tag,
			"-j", "NOTRACK",
		},
	}
	// mangle/OUTPUT drop RST flag on --sport: even with NOTRACK, the
	// kernel will produce RSTs in response to inbound SYNs / SYN-ACKs
	// addressed to the local pcap-recv port (which has no kernel
	// listener). Both sides need this rule, symmetric — pre-T4.9 the
	// client had no fixed local port so the rule was server-only;
	// T4.9 pins a real client port (so HELLO_ACK can be filtered in
	// via BPF), which also means the kernel will RST those inbound
	// SYNs without a DROP guard.
	//
	// The port the rule binds to is whichever port THIS side is
	// listening on with pcap — firewallPort() in cmd/run picks the
	// correct one per role: cfg.Listen.Addr.Port on the server,
	// cfg.Network.IPv4.Addr.Port (the client's pcap-recv port) on
	// the client. The isServer flag is retained only for the log
	// line in roleName(); the rule shape is identical.
	_ = isServer
	rules = append(rules, []string{
		"-t", "mangle",
		"-A", "OUTPUT",
		"-p", "tcp",
		"--sport", portStr,
		"--tcp-flags", "RST", "RST",
		"-m", "comment", "--comment", tag,
		"-j", "DROP",
	})
	return rules
}

// swapAction returns a copy of argv with the leading "-A" token replaced
// by newAction (typically "-D" for delete or "-C" for check). The
// "-A <chain>" pattern is the only place "-A" appears in any rule
// produced by buildApplyArgs, so the swap is unambiguous.
func swapAction(argv []string, newAction string) []string {
	out := make([]string, len(argv))
	copy(out, argv)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == "-A" {
			out[i] = newAction
			break
		}
	}
	return out
}
