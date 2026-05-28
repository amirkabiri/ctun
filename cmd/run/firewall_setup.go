package run

import (
	"context"
	"ctun/internal/conf"
	"ctun/internal/firewall"
	"ctun/internal/flog"
	"errors"
	"fmt"
	"runtime"
)

// firewallFactory is the dispatch point T4.4 uses to obtain a Manager
// for the current OS. Indirected through a package variable so the
// tests in firewall_setup_test.go can substitute a recording fake
// without touching the production code path. Production code always
// reads firewall.NewForCurrentOS via this variable.
var firewallFactory = firewall.NewForCurrentOS

// setupFirewall installs the per-OS firewall rules for the configured
// tunnel port and returns a cleanup function the caller must defer.
//
// The cleanup function:
//
//   - Is safe to call multiple times (Manager.Cleanup is idempotent on
//     all three backends — see internal/firewall/{linux,darwin,windows}.go).
//   - Tears down the SIGINT/SIGTERM signal hook installed by
//     firewall.InstallCleanup so a second run of cmd/run in the same
//     process (rare, but possible in tests) doesn't double-register.
//   - Tolerates "Apply partially succeeded" — Manager.Cleanup is
//     documented to remove what it installed and silently skip what
//     never made it onto the host.
//
// When conf.Firewall.Auto is false, setupFirewall logs an info message
// (the operator is responsible for installing rules manually) and
// returns a no-op cleanup so callers can defer unconditionally.
//
// When the host OS has no real firewall backend (the stub returns
// ErrNotImplemented from Apply), setupFirewall logs a warning and
// returns a no-op cleanup. Startup proceeds without installed rules —
// the kernel may still interfere with the synthetic flow, but that's
// a known limitation on unsupported OSes and not a reason to refuse
// to run.
//
// On any other Apply error the caller is expected to surface the error
// via flog.Fatalf — firewall rules are load-bearing and silently
// running without them produces confusing failures the operator
// cannot easily diagnose.
//
// The panic-recovery contract is documented on InstallCleanupForRun
// below; the deferred cleanup function returned here also runs from
// the panic path because the caller defers it before any code that
// might panic.
func setupFirewall(ctx context.Context, cfg *conf.Conf, isServer bool) (cleanup func(), err error) {
	if !cfg.Firewall.Auto {
		flog.Infof("firewall.auto=false; ctun will not install firewall rules. " +
			"The operator is responsible for installing the equivalent rules manually " +
			"(see README troubleshooting for the per-OS recipe).")
		return func() {}, nil
	}

	port, err := firewallPort(cfg, isServer)
	if err != nil {
		return nil, err
	}

	mgr := firewallFactory()
	if applyErr := mgr.Apply(port, isServer); applyErr != nil {
		// On platforms without a real backend (stub) the firewall package
		// returns ErrNotImplemented. Treat that as a warning, not a fatal:
		// ctun still runs, the operator just doesn't get auto-rule
		// management. Every other Apply error is fatal — see the comment
		// at the top of this function for why.
		if errors.Is(applyErr, firewall.ErrNotImplemented) {
			flog.Warnf("firewall: auto-management not supported on %s; "+
				"continuing without installed rules. Install the equivalent rules "+
				"manually if the host kernel interferes with the synthetic flow.",
				runtime.GOOS)
			return func() {}, nil
		}
		return nil, fmt.Errorf("firewall apply on port %d: %w", port, applyErr)
	}

	flog.Infof("firewall: installed rules for ctun-%d (role=%s)", port, roleName(isServer))

	// Wire SIGINT/SIGTERM and ctx-cancel to Cleanup. The unhook function
	// detaches the signal handler so the deferred cleanup below is the
	// final word — without the unhook a second SIGINT after a clean
	// shutdown could attempt a second Cleanup against an already-cleaned
	// manager. Manager.Cleanup tolerates that, but unhook keeps the
	// shutdown observable.
	unhook := firewall.InstallCleanup(ctx, mgr)

	cleanup = func() {
		// Cleanup is idempotent across the three backends, so calling it
		// here even if InstallCleanup already fired (e.g. on SIGINT) is
		// safe. The unhook is called first so any pending signal-driven
		// Cleanup goroutine doesn't race with the deferred path.
		unhook()
		if cerr := mgr.Cleanup(); cerr != nil {
			flog.Warnf("firewall cleanup failed: %v", cerr)
		}
	}
	return cleanup, nil
}

// firewallPort picks the local tunnel port THIS side listens on with
// pcap — the port the firewall rules need to tag.
//
// Server: cfg.Listen.Addr.Port (the published tunnel port).
// Client (T4.9): cfg.Network.IPv4.Addr.Port (the client's local
// pcap-recv port). Pre-T4.9 the client side passed
// cfg.Server.Addr.Port (i.e. the SERVER's port), which was correct
// for the outbound-NOTRACK-on-sport rule only by coincidence — the
// kernel-RST issue on the inbound HELLO_ACK was masked because the
// client port was zero and the BPF filter dropped every inbound
// packet at the pcap layer. Pinning a real client port surfaces the
// kernel-RST race; routing the firewall to the client's own port
// closes it.
//
// Both ports are validated to be non-zero by the conf package before
// this function is called.
func firewallPort(cfg *conf.Conf, isServer bool) (uint16, error) {
	var port int
	if isServer {
		if cfg.Listen.Addr == nil {
			return 0, errors.New("firewall: server listen address is nil; cannot determine tunnel port")
		}
		port = cfg.Listen.Addr.Port
	} else {
		// Client: pick the local pcap-recv port. Prefer IPv4 (the
		// configured family in every test/example fixture); IPv6 is
		// the fallback when only v6 is configured.
		switch {
		case cfg.Network.IPv4.Addr != nil:
			port = cfg.Network.IPv4.Addr.Port
		case cfg.Network.IPv6.Addr != nil:
			port = cfg.Network.IPv6.Addr.Port
		default:
			return 0, errors.New("firewall: client network address is nil; cannot determine local tunnel port")
		}
	}
	if port <= 0 || port > 0xFFFF {
		return 0, fmt.Errorf("firewall: tunnel port %d out of range", port)
	}
	return uint16(port), nil
}

// roleName returns a human-readable role string for log lines so the
// operator can distinguish server- vs client-side rule installs at a
// glance.
func roleName(isServer bool) string {
	if isServer {
		return "server"
	}
	return "client"
}

// runWithFirewall is the panic-aware wrapper every cmd/run entry
// point uses to make sure Cleanup runs on every exit path: clean
// return, SIGINT (handled by InstallCleanup), SIGTERM (ditto), and
// panic.
//
// The caller passes the cleanup closure returned from setupFirewall and
// the workload to run. If workload panics, runWithFirewall invokes
// cleanup before re-panicking so the operator never sees an orphan
// rule from a crashed ctun process (except in the kill -9 / SIGKILL
// case which is acknowledged as a known gap in the README).
//
// This indirection exists so the panic-recovery wrapping lives in one
// place — server.go and client.go both call runWithFirewall rather
// than each open-coding a `defer func() { recover() }`.
func runWithFirewall(cleanup func(), workload func()) {
	defer func() {
		if r := recover(); r != nil {
			cleanup()
			// Re-panic so the runtime's default panic handling (stack
			// trace to stderr, non-zero exit) still happens. Cleanup is
			// best-effort: if it itself panics we silently swallow that
			// here, because the original panic is more interesting.
			panic(r)
		}
		cleanup()
	}()
	workload()
}
