package run

import (
	"context"
	"ctun/internal/conf"
	"ctun/internal/firewall"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
)

// mockManager is a recording firewall.Manager used by every cmd/run test
// that wants to exercise the wiring without invoking the real per-OS
// backend (iptables / pfctl / netsh need root and would fail closed on
// a developer laptop). It records the (port, isServer) tuple passed to
// Apply and counts Cleanup invocations. Optional applyErr / cleanupErr
// fields let a test simulate failures.
//
// Safe for concurrent calls — every field that the InstallCleanup
// goroutine might touch in parallel with the main test goroutine uses
// atomics.
type mockManager struct {
	applyCalls   atomic.Int32
	cleanupCalls atomic.Int32

	lastPort     atomic.Uint32
	lastIsServer atomic.Bool

	applyErr   error
	cleanupErr error
}

func (m *mockManager) Apply(port uint16, isServer bool) error {
	m.applyCalls.Add(1)
	m.lastPort.Store(uint32(port))
	m.lastIsServer.Store(isServer)
	return m.applyErr
}

func (m *mockManager) Cleanup() error {
	m.cleanupCalls.Add(1)
	return m.cleanupErr
}

// withMockFirewall swaps the package-level firewallFactory for a test
// and restores it on Cleanup. The returned *mockManager is the one
// every call to firewallFactory will yield, so tests can assert against
// it after the workload runs.
func withMockFirewall(t *testing.T) *mockManager {
	t.Helper()
	m := &mockManager{}
	prev := firewallFactory
	firewallFactory = func() firewall.Manager { return m }
	t.Cleanup(func() { firewallFactory = prev })
	return m
}

// newConfForTest returns a minimally-populated *conf.Conf suitable for
// setupFirewall's port lookup. We fill in the fields setupFirewall
// touches: Firewall.Auto, Listen.Addr (server), and Network.IPv4.Addr
// (client — T4.9 changed firewallPort to use the client's own pcap-recv
// port rather than the destination server port).
func newConfForTest(auto bool, isServer bool, port int) *conf.Conf {
	c := &conf.Conf{}
	c.Firewall.Auto = auto
	if isServer {
		c.Listen.Addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	} else {
		c.Network.IPv4.Addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	}
	return c
}

// TestFirewallSetup_PicksManagerByGOOS verifies firewall.NewForCurrentOS
// returns the per-OS Manager appropriate for the current build. We can't
// test every GOOS in one process — Go's runtime.GOOS is fixed at compile
// time — but we CAN verify the function returns a non-nil Manager whose
// behaviour matches the expected per-OS contract: on linux/darwin/windows
// Apply with no rules + Cleanup with no Apply must NOT return
// ErrNotImplemented; on every other OS it MUST.
//
// The test does not actually invoke Apply because that would require
// root and would touch the real host firewall. It uses Cleanup as a
// proxy: every backend's Cleanup is a no-op when Apply was never
// called, so it's safe to call on any developer machine.
func TestFirewallSetup_PicksManagerByGOOS(t *testing.T) {
	mgr := firewall.NewForCurrentOS()
	if mgr == nil {
		t.Fatal("NewForCurrentOS returned nil")
	}
	// Cleanup must always be safe to call without a prior Apply, on
	// every OS. The stub's Cleanup returns ErrNotImplemented; the real
	// backends return nil because m.applied is false.
	err := mgr.Cleanup()
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		if err != nil {
			t.Errorf("on %s, Cleanup without Apply should be a no-op; got %v",
				runtime.GOOS, err)
		}
	default:
		// Stub platforms return ErrNotImplemented from every method.
		if !errors.Is(err, firewall.ErrNotImplemented) {
			t.Errorf("on %s, expected ErrNotImplemented from stub Cleanup; got %v",
				runtime.GOOS, err)
		}
	}
}

// TestFirewallSetup_RespectsAutoFalse verifies that when the operator
// disables auto-firewall management, setupFirewall does NOT call
// Apply / Cleanup on any manager. The returned cleanup function must
// still be a valid no-op the caller can defer unconditionally.
//
// This is the key contract for operators running their own
// configuration-management firewall: ctun must not silently overwrite
// or step on rules they installed themselves.
func TestFirewallSetup_RespectsAutoFalse(t *testing.T) {
	m := withMockFirewall(t)
	cfg := newConfForTest(false /* auto */, true /* server */, 9999)

	cleanup, err := setupFirewall(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("setupFirewall(auto=false) errored: %v", err)
	}
	if cleanup == nil {
		t.Fatal("setupFirewall(auto=false) returned nil cleanup; callers defer it unconditionally")
	}
	// The no-op cleanup must be safe to invoke.
	cleanup()

	if got := m.applyCalls.Load(); got != 0 {
		t.Errorf("auto=false: Apply should not be called; got %d invocations", got)
	}
	if got := m.cleanupCalls.Load(); got != 0 {
		t.Errorf("auto=false: Cleanup should not be called; got %d invocations", got)
	}
}

// TestFirewallSetup_AutoTrueInvokesApply verifies the happy path: when
// firewall.auto is true (the default), setupFirewall constructs the
// per-OS Manager and calls Apply with the configured port and the
// caller-supplied isServer flag. The returned cleanup, when invoked,
// must call Cleanup exactly once.
//
// We exercise both isServer=true and isServer=false in subtests so the
// argument plumbing is covered in both directions.
func TestFirewallSetup_AutoTrueInvokesApply(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		m := withMockFirewall(t)
		cfg := newConfForTest(true, true, 9999)

		cleanup, err := setupFirewall(context.Background(), cfg, true)
		if err != nil {
			t.Fatalf("setupFirewall: %v", err)
		}
		if got := m.applyCalls.Load(); got != 1 {
			t.Errorf("server-side Apply count: got %d, want 1", got)
		}
		if got := m.lastPort.Load(); got != 9999 {
			t.Errorf("server-side Apply port: got %d, want 9999", got)
		}
		if !m.lastIsServer.Load() {
			t.Error("server-side Apply isServer: got false, want true")
		}

		cleanup()
		if got := m.cleanupCalls.Load(); got != 1 {
			t.Errorf("cleanup count after one defer: got %d, want 1", got)
		}
	})

	t.Run("client", func(t *testing.T) {
		m := withMockFirewall(t)
		cfg := newConfForTest(true, false, 5555)

		cleanup, err := setupFirewall(context.Background(), cfg, false)
		if err != nil {
			t.Fatalf("setupFirewall: %v", err)
		}
		if got := m.applyCalls.Load(); got != 1 {
			t.Errorf("client-side Apply count: got %d, want 1", got)
		}
		if got := m.lastPort.Load(); got != 5555 {
			t.Errorf("client-side Apply port: got %d, want 5555", got)
		}
		if m.lastIsServer.Load() {
			t.Error("client-side Apply isServer: got true, want false")
		}

		cleanup()
		if got := m.cleanupCalls.Load(); got != 1 {
			t.Errorf("cleanup count after one defer: got %d, want 1", got)
		}
	})
}

// TestFirewallSetup_ApplyErrorPropagates verifies that a real Apply
// failure (anything not ErrNotImplemented) is surfaced as an error to
// the caller. The caller in cmd/run/{server,client}.go calls flog.Fatalf
// on a non-nil error, so this is the path that prevents a broken
// firewall install from silently producing a confused running ctun.
func TestFirewallSetup_ApplyErrorPropagates(t *testing.T) {
	m := withMockFirewall(t)
	m.applyErr = errors.New("synthetic iptables failure")
	cfg := newConfForTest(true, true, 9999)

	cleanup, err := setupFirewall(context.Background(), cfg, true)
	if err == nil {
		t.Fatal("expected Apply error to propagate; got nil")
	}
	if !errors.Is(err, m.applyErr) {
		t.Errorf("err chain should include the underlying Apply error; got %v", err)
	}
	if cleanup != nil {
		// The contract: on Apply failure, setupFirewall returns (nil, err)
		// because there's nothing for the caller to clean up.
		t.Error("on Apply error, cleanup should be nil; got non-nil")
	}
}

// TestFirewallSetup_NotImplementedIsWarning verifies the stub-platform
// path: when Apply returns ErrNotImplemented (today: every OS except
// linux/darwin/windows), setupFirewall must NOT propagate the error.
// Startup continues without installed rules, just with a logged warning.
// This is the contract the implementation-doc T4.4 DoD calls out as
// "log a clear warning and continue".
func TestFirewallSetup_NotImplementedIsWarning(t *testing.T) {
	m := withMockFirewall(t)
	m.applyErr = firewall.ErrNotImplemented
	cfg := newConfForTest(true, true, 9999)

	cleanup, err := setupFirewall(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("ErrNotImplemented should not propagate; got %v", err)
	}
	if cleanup == nil {
		t.Fatal("stub path should still return a non-nil no-op cleanup")
	}
	cleanup()
	if got := m.cleanupCalls.Load(); got != 0 {
		t.Errorf("stub path should not invoke Cleanup; got %d invocations", got)
	}
}

// TestFirewallPort verifies port extraction picks the right field per
// role and rejects nil / out-of-range values. The conf package validates
// these before setupFirewall sees them in production, but the explicit
// guard in firewallPort means a test or future caller that skips the
// full conf validation still gets a clear error rather than a panic on
// the nil-deref.
func TestFirewallPort(t *testing.T) {
	t.Run("server-listen", func(t *testing.T) {
		cfg := newConfForTest(true, true, 12345)
		port, err := firewallPort(cfg, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if port != 12345 {
			t.Errorf("got port %d, want 12345", port)
		}
	})
	t.Run("client-server", func(t *testing.T) {
		cfg := newConfForTest(true, false, 54321)
		port, err := firewallPort(cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if port != 54321 {
			t.Errorf("got port %d, want 54321", port)
		}
	})
	t.Run("nil-listen-addr", func(t *testing.T) {
		cfg := &conf.Conf{}
		_, err := firewallPort(cfg, true)
		if err == nil {
			t.Error("expected error for nil Listen.Addr; got nil")
		}
	})
	t.Run("nil-client-network-addr", func(t *testing.T) {
		// T4.9: client firewall now keys on cfg.Network.IPv4/IPv6.Addr
		// instead of cfg.Server.Addr. An empty Conf still has no
		// configured client port; firewallPort returns an error.
		cfg := &conf.Conf{}
		_, err := firewallPort(cfg, false)
		if err == nil {
			t.Error("expected error for nil Network IPv4/IPv6 Addr; got nil")
		}
	})
	t.Run("port-out-of-range", func(t *testing.T) {
		cfg := newConfForTest(true, true, 0)
		_, err := firewallPort(cfg, true)
		if err == nil {
			t.Error("expected error for port 0; got nil")
		}
	})
}
