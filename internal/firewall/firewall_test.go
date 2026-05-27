package firewall

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestErrNotImplemented_IsTyped pins that ErrNotImplemented is comparable
// with errors.Is even after a typical fmt.Errorf wrap. The cleanup wiring
// in T4.4 will likely wrap firewall errors with context (e.g. the port,
// the operation) before logging them; that wrapping must not break a
// caller's branch on the typed error.
func TestErrNotImplemented_IsTyped(t *testing.T) {
	if !errors.Is(ErrNotImplemented, ErrNotImplemented) {
		t.Fatal("errors.Is(ErrNotImplemented, ErrNotImplemented) should be true")
	}

	wrapped := fmt.Errorf("firewall apply: %w", ErrNotImplemented)
	if !errors.Is(wrapped, ErrNotImplemented) {
		t.Fatal("errors.Is(wrapped, ErrNotImplemented) should be true")
	}

	other := errors.New("some other error")
	if errors.Is(other, ErrNotImplemented) {
		t.Fatal("errors.Is(other, ErrNotImplemented) should be false")
	}
}

// TestLinuxManager_BuildArgs locks in the exact iptables argv that the
// Linux backend executes. Runs on every platform — buildApplyArgs is pure
// argv construction with no exec calls, so macOS developers can verify
// the rule shape without a Linux runner. If a maintainer needs to change
// the rule shape (e.g. add a flag), they update buildApplyArgs and these
// expected vectors in one diff so the cleanup path stays in sync.
//
// The expected vectors below correspond 1:1 to the manual recipe in
// example/server.yaml.example, with the ctun-<port> comment tag added.
func TestLinuxManager_BuildArgs(t *testing.T) {
	clientArgs := buildApplyArgs(9999, false)
	if len(clientArgs) != 2 {
		t.Fatalf("client side should emit exactly 2 rules; got %d: %v", len(clientArgs), clientArgs)
	}

	serverArgs := buildApplyArgs(9999, true)
	if len(serverArgs) != 3 {
		t.Fatalf("server side should emit exactly 3 rules; got %d: %v", len(serverArgs), serverArgs)
	}

	wantClient := [][]string{
		{
			"-t", "raw",
			"-A", "PREROUTING",
			"-p", "tcp",
			"--dport", "9999",
			"-m", "comment", "--comment", "ctun-9999",
			"-j", "NOTRACK",
		},
		{
			"-t", "raw",
			"-A", "OUTPUT",
			"-p", "tcp",
			"--sport", "9999",
			"-m", "comment", "--comment", "ctun-9999",
			"-j", "NOTRACK",
		},
	}
	if !reflect.DeepEqual(clientArgs, wantClient) {
		t.Errorf("client argv mismatch\n got:  %v\n want: %v", clientArgs, wantClient)
	}

	wantServer := append([][]string{}, wantClient...)
	wantServer = append(wantServer, []string{
		"-t", "mangle",
		"-A", "OUTPUT",
		"-p", "tcp",
		"--sport", "9999",
		"--tcp-flags", "RST", "RST",
		"-m", "comment", "--comment", "ctun-9999",
		"-j", "DROP",
	})
	if !reflect.DeepEqual(serverArgs, wantServer) {
		t.Errorf("server argv mismatch\n got:  %v\n want: %v", serverArgs, wantServer)
	}

	// Sanity: every rule must include the comment tag, otherwise Cleanup
	// has no way to identify ctun's rules among unrelated entries on the
	// host. This invariant is enforced here so a future "minor" edit to
	// buildApplyArgs that drops the comment trips the test rather than
	// silently breaking cleanup.
	for i, argv := range serverArgs {
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, "--comment ctun-9999") {
			t.Errorf("rule %d missing ctun-<port> comment tag: %s", i, joined)
		}
	}
}

// TestSwapAction verifies the -A → -D / -A → -C swap helper that the
// Linux backend uses to derive the delete and check argv from the install
// argv. Trivial but load-bearing: a bug here would silently make Cleanup
// a no-op.
func TestSwapAction(t *testing.T) {
	in := []string{"-t", "raw", "-A", "PREROUTING", "-j", "NOTRACK"}
	got := swapAction(in, "-D")
	want := []string{"-t", "raw", "-D", "PREROUTING", "-j", "NOTRACK"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("swapAction(-D) mismatch\n got:  %v\n want: %v", got, want)
	}

	// The input must NOT be mutated — Cleanup reuses the same argv across
	// multiple swap actions in a loop.
	if !reflect.DeepEqual(in, []string{"-t", "raw", "-A", "PREROUTING", "-j", "NOTRACK"}) {
		t.Errorf("swapAction mutated input: %v", in)
	}

	gotC := swapAction(in, "-C")
	wantC := []string{"-t", "raw", "-C", "PREROUTING", "-j", "NOTRACK"}
	if !reflect.DeepEqual(gotC, wantC) {
		t.Errorf("swapAction(-C) mismatch\n got:  %v\n want: %v", gotC, wantC)
	}
}

// TestCommentTag verifies the port-to-tag mapping is what the rest of the
// stack (linux.go, future darwin.go / windows.go, and external operators
// running `iptables-save | grep`) expects.
func TestCommentTag(t *testing.T) {
	cases := []struct {
		port uint16
		want string
	}{
		{port: 9999, want: "ctun-9999"},
		{port: 0, want: "ctun-0"},
		{port: 65535, want: "ctun-65535"},
	}
	for _, c := range cases {
		if got := commentTag(c.port); got != c.want {
			t.Errorf("commentTag(%d) = %q; want %q", c.port, got, c.want)
		}
	}
}
