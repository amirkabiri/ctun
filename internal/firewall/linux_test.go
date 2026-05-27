//go:build linux

package firewall

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// requireRoot skips the test if the process is not running as root. The
// iptables-touching tests need CAP_NET_ADMIN which on a stock Linux box
// requires root; we'd rather skip cleanly than fail on a developer laptop.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (sets real iptables rules)")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables binary not found in PATH")
	}
}

// iptablesSave returns the output of `iptables-save` so the test can grep
// for the ctun-<port> comment to assert presence / absence / count of rules.
func iptablesSave(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		t.Fatalf("iptables-save failed: %v", err)
	}
	return string(out)
}

// countCtunRules returns the number of lines in `iptables-save` output
// that reference the ctun-<port> tag. Each installed rule contributes
// exactly one matching line, so this is also the rule count.
func countCtunRules(save string, port uint16) int {
	tag := commentTag(port)
	count := 0
	for _, line := range strings.Split(save, "\n") {
		if strings.Contains(line, tag) {
			count++
		}
	}
	return count
}

// testPort is intentionally a high, unusual port so the test doesn't
// collide with anything the host might actually run.
const testPort uint16 = 9999

// TestLinuxManager_Apply_Idempotent verifies that calling Apply twice with
// the same arguments does not duplicate rules. The check uses iptables-save
// because that's the authoritative view of installed rules and is exactly
// what an operator would use to debug.
func TestLinuxManager_Apply_Idempotent(t *testing.T) {
	requireRoot(t)

	mgr := NewLinux()
	t.Cleanup(func() { _ = mgr.Cleanup() })

	if err := mgr.Apply(testPort, true); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}
	firstCount := countCtunRules(iptablesSave(t), testPort)
	if firstCount != 3 {
		t.Fatalf("after first Apply (server), expected 3 ctun-<port> rules; got %d", firstCount)
	}

	if err := mgr.Apply(testPort, true); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	secondCount := countCtunRules(iptablesSave(t), testPort)
	if secondCount != firstCount {
		t.Fatalf("Apply not idempotent: rule count went %d → %d", firstCount, secondCount)
	}
}

// TestLinuxManager_Cleanup_RemovesAll verifies Cleanup removes every rule
// previously installed by Apply, identified by the ctun-<port> tag.
func TestLinuxManager_Cleanup_RemovesAll(t *testing.T) {
	requireRoot(t)

	mgr := NewLinux()
	if err := mgr.Apply(testPort, true); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if got := countCtunRules(iptablesSave(t), testPort); got == 0 {
		t.Fatalf("Apply succeeded but no ctun-<port> rules visible")
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if got := countCtunRules(iptablesSave(t), testPort); got != 0 {
		t.Fatalf("Cleanup did not remove all rules; %d ctun-<port> rules remain", got)
	}
}

// TestLinuxManager_Cleanup_ToleratesAbsentRules verifies Cleanup is safe to
// invoke from a defer / panic-recovery path even when Apply was never
// called (or already cleaned up). This is the contract every panic-handler
// caller relies on.
func TestLinuxManager_Cleanup_ToleratesAbsentRules(t *testing.T) {
	requireRoot(t)

	mgr := NewLinux()
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup with no prior Apply should not error; got: %v", err)
	}

	// Also tolerate a second Cleanup after a successful Apply+Cleanup.
	if err := mgr.Apply(testPort, false); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("first Cleanup failed: %v", err)
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("second Cleanup should be a no-op; got: %v", err)
	}
}
