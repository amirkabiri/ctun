//go:build windows

package firewall

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// windowsTestPort matches the testPort used by the Linux and darwin tests
// so an operator who runs the suites on multiple OSes isn't juggling
// different "scratch" ports. Intentionally a high, unusual port that
// nothing on a stock developer Windows box should be listening on.
const windowsTestPort uint16 = 9999

// requireAdminWindows skips the test if the process is not running with
// the privileges netsh requires to mutate the firewall configuration.
// Go cannot easily detect "admin" on Windows from inside the runtime
// (the closest signal — `OpenProcessToken` + `GetTokenInformation` —
// requires more cgo than the project budget allows here), so we gate
// the tests behind a sentinel environment variable: CTUN_TEST_ADMIN=1
// must be set explicitly by the CI runner or the developer that knows
// they invoked the tests from an elevated shell. The matching shape on
// Linux/darwin is `os.Geteuid() != 0`; the env-var sentinel is a
// platform-appropriate analogue.
func requireAdminWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("CTUN_TEST_ADMIN") != "1" {
		t.Skip("test requires admin (set CTUN_TEST_ADMIN=1 when invoking from an elevated shell)")
	}
	if _, err := exec.LookPath("netsh"); err != nil {
		t.Skip("netsh binary not found in PATH")
	}
}

// netshShowRule runs `netsh advfirewall firewall show rule name=<name>`
// and returns its stdout for the test to grep. An absent rule causes
// netsh to exit 1 with "No rules match the specified criteria." — we
// still return the stdout so the test can branch on the canonical
// message.
func netshShowRule(t *testing.T, port uint16) string {
	t.Helper()
	out, _ := exec.Command("netsh", "advfirewall", "firewall", "show", "rule",
		"name="+ruleName(port)).Output()
	return string(out)
}

// ruleInstalled reports whether the rule for the given port is currently
// registered with Windows Firewall. Uses the same canonical-string
// heuristic ruleExists in windows.go uses, so the test and the
// production code agree on what "present" means.
func ruleInstalled(t *testing.T, port uint16) bool {
	t.Helper()
	stdout := netshShowRule(t, port)
	if strings.Contains(stdout, "No rules match") {
		return false
	}
	// netsh prints "Rule Name:" once per matching rule on Windows;
	// a present rule always has at least one such line.
	return strings.Contains(stdout, "Rule Name:") || strings.Contains(stdout, ruleName(port))
}

// TestWindowsManager_Apply_Idempotent verifies that calling Apply twice
// with the same arguments does not install two rules with the same name.
// netsh's `add rule` is *not* natively idempotent — it will happily
// install duplicates — so this test specifically exercises the
// ruleExists pre-check Apply runs.
//
// Gated on admin via CTUN_TEST_ADMIN=1. Skipped on non-elevated runs.
func TestWindowsManager_Apply_Idempotent(t *testing.T) {
	requireAdminWindows(t)

	mgr := NewWindows()
	t.Cleanup(func() { _ = mgr.Cleanup() })

	if err := mgr.Apply(windowsTestPort, true); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}
	if !ruleInstalled(t, windowsTestPort) {
		t.Fatalf("after first Apply, rule should be visible via netsh show rule")
	}

	if err := mgr.Apply(windowsTestPort, true); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	// The rule should still be present — and there should be exactly one
	// of it. netsh prints one "Rule Name:" line per matching rule; we
	// count them to confirm Apply didn't duplicate.
	stdout := netshShowRule(t, windowsTestPort)
	count := strings.Count(stdout, "Rule Name:")
	if count != 1 {
		t.Fatalf("Apply not idempotent: expected exactly 1 rule with name %q, got %d (output: %q)",
			ruleName(windowsTestPort), count, stdout)
	}
}

// TestWindowsManager_Cleanup_RemovesRule verifies Cleanup deletes the
// rule previously installed by Apply.
//
// Gated on admin via CTUN_TEST_ADMIN=1. Skipped on non-elevated runs.
func TestWindowsManager_Cleanup_RemovesRule(t *testing.T) {
	requireAdminWindows(t)

	mgr := NewWindows()
	if err := mgr.Apply(windowsTestPort, true); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if !ruleInstalled(t, windowsTestPort) {
		t.Fatalf("Apply succeeded but rule not visible via netsh show rule")
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if ruleInstalled(t, windowsTestPort) {
		t.Fatalf("Cleanup did not remove the rule")
	}
}

// TestWindowsManager_Cleanup_ToleratesAbsentRule verifies Cleanup is safe
// to invoke from a defer / panic-recovery path even when Apply was never
// called (or already cleaned up). This is the contract every
// panic-handler caller relies on, matched against the Linux and darwin
// implementations.
//
// The no-Apply branch does NOT require admin because it short-circuits
// on m.applied == false; the post-Apply-cycle branch is gated on admin
// and skipped on non-elevated runs.
func TestWindowsManager_Cleanup_ToleratesAbsentRule(t *testing.T) {
	mgr := NewWindows()
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup with no prior Apply should not error; got: %v", err)
	}

	// Second Cleanup after the first should also be a no-op.
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("second Cleanup with no prior Apply should not error; got: %v", err)
	}

	// And a Cleanup after a successful Apply+Cleanup cycle should still
	// be a no-op. Requires admin for the Apply, so gate that branch.
	if os.Getenv("CTUN_TEST_ADMIN") != "1" {
		t.Log("skipping post-Apply-cycle branch (requires CTUN_TEST_ADMIN=1)")
		return
	}
	if _, err := exec.LookPath("netsh"); err != nil {
		t.Skip("netsh binary not found in PATH")
	}
	if err := mgr.Apply(windowsTestPort, false); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("first Cleanup after Apply failed: %v", err)
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("second Cleanup after Apply should be a no-op; got: %v", err)
	}
}

// TestWindowsManager_BuildArgs locks in the exact netsh argv that the
// Windows backend executes. Runs on every Windows build without admin —
// buildAddArgs / buildDeleteArgs / buildExistsArgs are pure argv
// construction with no exec calls, so the rule shape can be verified
// without an elevated shell. If a maintainer needs to change the rule
// shape (e.g. add a remoteip filter), they update the builders and
// these expected vectors in one diff so the install path and the
// cleanup path stay in sync.
func TestWindowsManager_BuildArgs(t *testing.T) {
	wantAdd := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=ctun-9999",
		"dir=in",
		"action=block",
		"protocol=TCP",
		"localport=9999",
	}
	if got := buildAddArgs(9999); !reflect.DeepEqual(got, wantAdd) {
		t.Errorf("buildAddArgs(9999) mismatch\n got:  %v\n want: %v", got, wantAdd)
	}

	wantDelete := []string{
		"advfirewall", "firewall", "delete", "rule",
		"name=ctun-9999",
	}
	if got := buildDeleteArgs(9999); !reflect.DeepEqual(got, wantDelete) {
		t.Errorf("buildDeleteArgs(9999) mismatch\n got:  %v\n want: %v", got, wantDelete)
	}

	wantExists := []string{
		"advfirewall", "firewall", "show", "rule",
		"name=ctun-9999",
	}
	if got := buildExistsArgs(9999); !reflect.DeepEqual(got, wantExists) {
		t.Errorf("buildExistsArgs(9999) mismatch\n got:  %v\n want: %v", got, wantExists)
	}

	// Sanity: every argv must carry the ctun-<port> name=… token,
	// otherwise the install path and the cleanup path lose the only
	// identifier that ties them together. Pin it here so a future
	// "minor" edit to the builders that drops the name trips the test
	// rather than silently breaking cleanup.
	for label, argv := range map[string][]string{
		"add":    buildAddArgs(9999),
		"delete": buildDeleteArgs(9999),
		"show":   buildExistsArgs(9999),
	} {
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, "name=ctun-9999") {
			t.Errorf("%s argv missing name=ctun-<port> token: %s", label, joined)
		}
	}

	// Confirm the rule-name format separately for the same reason
	// TestCommentTag / TestAnchorName pin their respective formats:
	// external operators running `netsh advfirewall firewall show rule
	// name=ctun-<port>` rely on this exact spelling.
	cases := []struct {
		port uint16
		want string
	}{
		{port: 9999, want: "ctun-9999"},
		{port: 0, want: "ctun-0"},
		{port: 65535, want: "ctun-65535"},
	}
	for _, c := range cases {
		if got := ruleName(c.port); got != c.want {
			t.Errorf("ruleName(%d) = %q; want %q", c.port, got, c.want)
		}
	}
}

// stubExecCommandWindows is provided for parity with darwin's
// stubExecCommand — a test that wants to exercise the windowsManager's
// state machine without actually invoking netsh can install this hook.
// No test in this file uses it today; it's here so future
// non-admin-gated tests (e.g. a state-machine torture test) have a
// known-good stub to plug in.
//
// Returns an *exec.Cmd that runs `cmd /c rem` — a true no-op on every
// Windows host with the standard cmd shell available. Exits 0 with no
// output, exactly the success signal Apply expects from netsh.
//
//nolint:unused // reserved for future tests; see comment above.
func stubExecCommandWindows(ctx context.Context, name string, arg ...string) *exec.Cmd {
	_ = name
	_ = arg
	cmd := exec.CommandContext(ctx, "cmd", "/c", "rem")
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &bytes.Buffer{}
	return cmd
}
