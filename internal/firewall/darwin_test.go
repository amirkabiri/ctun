//go:build darwin

package firewall

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// darwinTestPort matches the testPort used by the Linux tests so an
// operator who runs both suites isn't juggling two different "scratch"
// ports. Intentionally a high, unusual port that nothing on a stock
// developer macOS box should be listening on.
const darwinTestPort uint16 = 9999

// requireRootDarwin skips the test if the process is not running as root.
// pfctl needs effective uid 0 to load anchor rules on macOS; we'd rather
// skip cleanly than fail on a developer laptop without sudo cached.
func requireRootDarwin(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (loads real pf anchor rules)")
	}
	if _, err := exec.LookPath("pfctl"); err != nil {
		t.Skip("pfctl binary not found in PATH")
	}
}

// pfctlAnchorRules returns the output of `pfctl -a ctun.<port> -s rules`
// so the test can assert presence / absence of rules under the anchor.
// An empty anchor produces an empty string (modulo whitespace); a flushed
// or never-loaded anchor likewise produces empty.
func pfctlAnchorRules(t *testing.T, port uint16) string {
	t.Helper()
	out, err := exec.Command("pfctl", "-a", anchorName(port), "-s", "rules").Output()
	if err != nil {
		// pfctl prints diagnostic messages to stderr; the absence of an
		// anchor isn't an error condition for our purposes. Surface the
		// error so the test author sees what's going on, but don't fail
		// the test on the lookup itself.
		t.Logf("pfctl -a %s -s rules returned error %v (treating as empty)", anchorName(port), err)
		return ""
	}
	return string(out)
}

// TestDarwinManager_Apply_Idempotent verifies that calling Apply twice
// with the same arguments does not duplicate rules. pfctl's `-f` replaces
// the anchor's ruleset wholesale on each invocation, so this is more of
// a smoke test than a real idempotency torture test — but it pins the
// behaviour against any future regression that switches to a non-replacing
// load mode.
func TestDarwinManager_Apply_Idempotent(t *testing.T) {
	requireRootDarwin(t)

	mgr := NewDarwin()
	t.Cleanup(func() { _ = mgr.Cleanup() })

	if err := mgr.Apply(darwinTestPort, true); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}
	firstRules := pfctlAnchorRules(t, darwinTestPort)
	firstCount := countRuleLines(firstRules)
	if firstCount != 2 {
		t.Fatalf("after first Apply (server), expected 2 rules in anchor; got %d (output: %q)", firstCount, firstRules)
	}

	if err := mgr.Apply(darwinTestPort, true); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	secondRules := pfctlAnchorRules(t, darwinTestPort)
	secondCount := countRuleLines(secondRules)
	if secondCount != firstCount {
		t.Fatalf("Apply not idempotent: rule count went %d → %d", firstCount, secondCount)
	}
}

// TestDarwinManager_Cleanup_RemovesAnchor verifies Cleanup flushes every
// rule under the anchor, leaving it empty.
func TestDarwinManager_Cleanup_RemovesAnchor(t *testing.T) {
	requireRootDarwin(t)

	mgr := NewDarwin()
	if err := mgr.Apply(darwinTestPort, true); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if got := countRuleLines(pfctlAnchorRules(t, darwinTestPort)); got == 0 {
		t.Fatalf("Apply succeeded but no rules visible under anchor")
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if got := countRuleLines(pfctlAnchorRules(t, darwinTestPort)); got != 0 {
		t.Fatalf("Cleanup did not flush all rules; %d remain", got)
	}
}

// TestDarwinManager_Cleanup_ToleratesAbsentAnchor verifies Cleanup is safe
// to invoke from a defer / panic-recovery path even when Apply was never
// called (or already cleaned up). This is the contract every panic-handler
// caller relies on.
func TestDarwinManager_Cleanup_ToleratesAbsentAnchor(t *testing.T) {
	// This test does NOT require root because the no-Apply path never
	// touches pfctl — it short-circuits on m.applied == false.
	mgr := NewDarwin()
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup with no prior Apply should not error; got: %v", err)
	}

	// Second Cleanup after the first should also be a no-op.
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("second Cleanup with no prior Apply should not error; got: %v", err)
	}

	// And a Cleanup after a successful Apply+Cleanup cycle should still
	// be a no-op. Requires root for the Apply, so gate that branch.
	if os.Geteuid() != 0 {
		t.Log("skipping post-Apply-cycle branch (requires root)")
		return
	}
	if _, err := exec.LookPath("pfctl"); err != nil {
		t.Skip("pfctl binary not found in PATH")
	}
	if err := mgr.Apply(darwinTestPort, false); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("first Cleanup after Apply failed: %v", err)
	}
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("second Cleanup after Apply should be a no-op; got: %v", err)
	}
}

// TestDarwinManager_TempfileLifecycle verifies the tempfile path is what
// the rest of the code expects (stable per port under os.TempDir()) and
// that Cleanup removes it. Uses a stub execCommand so the test does not
// require root: the only thing being asserted is the filesystem lifecycle,
// not the pfctl integration.
func TestDarwinManager_TempfileLifecycle(t *testing.T) {
	// Pin the expected path. If this constant drifts, the design
	// invariant ("stable tempfile per port") has broken.
	wantPath := filepath.Join(os.TempDir(), "ctun-"+strconv.FormatUint(uint64(darwinTestPort), 10)+".anchor")
	if got := tmpfilePathFor(darwinTestPort); got != wantPath {
		t.Fatalf("tmpfilePathFor(%d) = %q; want %q", darwinTestPort, got, wantPath)
	}

	// Pre-clean in case a previous failed test left the file behind.
	_ = os.Remove(wantPath)

	mgr := &darwinManager{execCommand: stubExecCommand}
	if err := mgr.Apply(darwinTestPort, true); err != nil {
		t.Fatalf("Apply (stubbed) failed: %v", err)
	}

	// The tempfile must exist after Apply.
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("tempfile should exist after Apply; stat err: %v", err)
	}

	// Its contents must match what buildAnchorBody returns for the same
	// args. This is the contract Cleanup relies on: re-Apply rewrites
	// the same path with the same content.
	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read tempfile: %v", err)
	}
	want := buildAnchorBody(darwinTestPort, true)
	if string(got) != want {
		t.Fatalf("tempfile content mismatch\n got:  %q\n want: %q", string(got), want)
	}

	// The manager must remember the path so Cleanup can target it.
	if mgr.tmpfilePath != wantPath {
		t.Fatalf("darwinManager.tmpfilePath = %q; want %q", mgr.tmpfilePath, wantPath)
	}

	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup (stubbed) failed: %v", err)
	}

	// The tempfile must be gone after Cleanup.
	if _, err := os.Stat(wantPath); !os.IsNotExist(err) {
		// Cleanup left the file behind — that's the bug.
		_ = os.Remove(wantPath) // best-effort cleanup so we don't litter
		t.Fatalf("tempfile should be removed by Cleanup; stat err: %v", err)
	}

	// The manager's recorded path should be cleared so a future Cleanup
	// is unambiguously a no-op.
	if mgr.tmpfilePath != "" {
		t.Errorf("darwinManager.tmpfilePath should be cleared after Cleanup; got %q", mgr.tmpfilePath)
	}
}

// TestBuildAnchorBody locks in the exact pf rule body emitted for both
// the server-side and client-side anchors. Runs on every darwin build —
// buildAnchorBody is pure string construction with no exec calls.
//
// If a maintainer changes the rule shape (e.g. adds an interface match),
// they update buildAnchorBody and this expected string in one diff so
// the test catches drift between the install path and the cleanup path
// (Cleanup doesn't read the body, but the operator-facing semantics
// depend on the body matching what's documented in design-doc §12).
func TestBuildAnchorBody(t *testing.T) {
	// Client side: anchor body must be empty. The client doesn't listen
	// on the tunnel port, so no kernel-generated traffic to block; the
	// anchor exists only so Cleanup has a target.
	if got := buildAnchorBody(9999, false); got != "" {
		t.Errorf("client anchor body should be empty; got %q", got)
	}

	// Server side: two `block drop quick` rules, one per direction.
	wantServer := "block drop quick proto tcp from any to any port 9999\n" +
		"block drop quick proto tcp from any port 9999 to any\n"
	if got := buildAnchorBody(9999, true); got != wantServer {
		t.Errorf("server anchor body mismatch\n got:  %q\n want: %q", got, wantServer)
	}

	// Sanity: the rule body must use `block drop`, not `block return-rst`.
	// The whole point of the server-side rule is to prevent the kernel
	// from generating RSTs, so an accidental switch to return-rst would
	// silently defeat the firewall. Pin it here.
	if strings.Contains(buildAnchorBody(9999, true), "return-rst") {
		t.Error("server anchor body must not contain return-rst (defeats the purpose)")
	}
}

// TestAnchorName locks in the anchor naming convention. External operators
// running `pfctl -a ctun.<port> -s rules` rely on this format; a drift here
// would silently break their muscle-memory diagnostic path.
func TestAnchorName(t *testing.T) {
	cases := []struct {
		port uint16
		want string
	}{
		{port: 9999, want: "ctun.9999"},
		{port: 0, want: "ctun.0"},
		{port: 65535, want: "ctun.65535"},
	}
	for _, c := range cases {
		if got := anchorName(c.port); got != c.want {
			t.Errorf("anchorName(%d) = %q; want %q", c.port, got, c.want)
		}
	}
}

// countRuleLines counts non-empty, non-comment lines in pfctl `-s rules`
// output. pfctl prints one rule per line; blank lines and shell-style
// comments (`#`) are noise.
func countRuleLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		n++
	}
	return n
}

// stubExecCommand replaces exec.CommandContext for tests that want to
// exercise the tempfile lifecycle without actually invoking pfctl. It
// returns an exec.Cmd that points at /bin/true (or `true` on the PATH),
// which exits 0 with no output — exactly the success signal Apply expects
// from pfctl when the anchor loads cleanly.
func stubExecCommand(ctx context.Context, name string, arg ...string) *exec.Cmd {
	_ = name
	_ = arg
	cmd := exec.CommandContext(ctx, "/usr/bin/true")
	// Make sure no stray FDs leak into the child; the production code
	// installs explicit bytes.Buffer Writers, but be defensive in case a
	// future refactor leaves stdio at the inherited defaults.
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &bytes.Buffer{}
	return cmd
}
