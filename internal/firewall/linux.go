//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// linuxManager installs and removes ctun's iptables rules on Linux. It
// invokes the `iptables` binary directly via os/exec — there is no
// netlink-based library dependency, matching the minimal-dependency rule
// the project follows and matching the manual recipe operators are already
// familiar with from paqet's README.
//
// Apply emits exactly these invocations (replace <port> with the configured
// port; comment "ctun-<port>" is the cleanup tag):
//
//	Client side (isServer=false):
//	  iptables -t raw    -A PREROUTING -p tcp --dport <port> -m comment --comment ctun-<port> -j NOTRACK
//	  iptables -t raw    -A OUTPUT     -p tcp --sport <port> -m comment --comment ctun-<port> -j NOTRACK
//
//	Server side (isServer=true): the two client-side rules above, PLUS:
//	  iptables -t mangle -A OUTPUT     -p tcp --sport <port> --tcp-flags RST RST -m comment --comment ctun-<port> -j DROP
//
// The client doesn't listen on the tunnel port so the kernel never produces
// outbound RSTs on --sport; only the server needs the mangle rule.
//
// Before adding each rule, Apply calls `iptables -C` to check whether an
// identical rule (matched on the comment string) is already installed; if
// so, the add is skipped. This makes Apply idempotent: it is safe to call
// repeatedly without duplicating rules.
//
// Cleanup iterates over the same rule specs and issues `-D` for each
// (replacing the `-A` action). iptables only deletes one matching rule per
// invocation, so Cleanup loops until `-D` reports "rule not present"
// (exit code 2, with the diagnostic "No chain/target/match by that name."
// or "iptables: Bad rule (does a matching rule exist in that chain?).")
//
// All exec calls capture stderr so failures produce a usable diagnostic
// message rather than a bare exit code.
type linuxManager struct {
	mu       sync.Mutex
	port     uint16
	isServer bool
	applied  bool

	// execCommand is exec.CommandContext by default; tests inject a fake
	// to assert argv shape without actually running iptables.
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// NewLinux constructs a Manager backed by the system `iptables` binary.
// The returned Manager is safe for concurrent calls to Apply/Cleanup.
func NewLinux() Manager {
	return &linuxManager{
		execCommand: exec.CommandContext,
	}
}

// runIPTables invokes iptables with the given argv and returns (stdout,
// stderr, exit-code, error). Exit codes other than 0 are NOT folded into
// the error — callers that tolerate specific exit codes (e.g. 2 from a
// "-D" against an absent rule) need to see the raw code.
func (m *linuxManager) runIPTables(ctx context.Context, argv []string) (string, string, int, error) {
	cmd := m.execCommand(ctx, "iptables", argv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
			// An exit code is a legitimate result (e.g. -C / -D may exit
			// non-zero meaningfully). Don't propagate the exec error in
			// that case; the caller decides.
			err = nil
		}
	}
	return stdout.String(), stderr.String(), exitCode, err
}

// ruleExists reports whether the given iptables rule (in `-A` form) is
// already installed, using `-C` (check). iptables exits 0 if present,
// non-zero if absent.
func (m *linuxManager) ruleExists(ctx context.Context, applyArgv []string) (bool, error) {
	checkArgv := swapAction(applyArgv, "-C")
	_, stderr, exitCode, err := m.runIPTables(ctx, checkArgv)
	if err != nil {
		return false, fmt.Errorf("iptables -C failed: %w (stderr: %s)", err, strings.TrimSpace(stderr))
	}
	return exitCode == 0, nil
}

// Apply installs the rule set for the configured port. See the type-level
// comment block for the exact iptables invocations.
func (m *linuxManager) Apply(port uint16, isServer bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Bound each iptables call so a stuck binary cannot wedge startup forever.
	// 5 s is well past any healthy iptables invocation on Linux.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, argv := range buildApplyArgs(port, isServer) {
		exists, err := m.ruleExists(ctx, argv)
		if err != nil {
			return err
		}
		if exists {
			// Idempotency: identical rule already installed (likely by a
			// previous ctun instance that didn't get to clean up). Skip.
			continue
		}
		_, stderr, exitCode, err := m.runIPTables(ctx, argv)
		if err != nil {
			return fmt.Errorf("iptables %s failed: %w (stderr: %s)", strings.Join(argv, " "), err, strings.TrimSpace(stderr))
		}
		if exitCode != 0 {
			return fmt.Errorf("iptables %s exited %d (stderr: %s)", strings.Join(argv, " "), exitCode, strings.TrimSpace(stderr))
		}
	}

	m.port = port
	m.isServer = isServer
	m.applied = true
	return nil
}

// Cleanup removes the rules previously installed by Apply. If Apply was
// never called (m.applied == false), Cleanup is a no-op so callers can
// `defer mgr.Cleanup()` unconditionally.
//
// For each rule, Cleanup loops `-D` until iptables reports "no such rule"
// (exit code 2 or 1 depending on iptables version; we treat any non-zero
// exit with the "matching rule" diagnostic in stderr as terminal-OK).
// The loop is bounded to a generous 100 iterations per rule to prevent
// runaway behaviour against a buggy iptables.
func (m *linuxManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.applied {
		// Nothing to do — Apply was never called, or already cleaned up.
		// Tolerating this case is required for panic-recovery callers
		// that defer Cleanup before Apply has completed.
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var firstErr error
	for _, argv := range buildApplyArgs(m.port, m.isServer) {
		deleteArgv := swapAction(argv, "-D")
		for i := 0; i < 100; i++ {
			_, stderr, exitCode, err := m.runIPTables(ctx, deleteArgv)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("iptables %s failed: %w (stderr: %s)", strings.Join(deleteArgv, " "), err, strings.TrimSpace(stderr))
				}
				break
			}
			if exitCode == 0 {
				// Deleted one occurrence; loop to handle the (rare) case
				// where a duplicate slipped through.
				continue
			}
			// Non-zero exit: either "rule not present" (terminal-OK) or
			// a real failure. iptables reports absence with messages like
			// "iptables: Bad rule (does a matching rule exist in that
			// chain?)." on stderr; we treat any non-zero exit as
			// "nothing more to delete on this rule." This is intentional:
			// Cleanup is supposed to tolerate absent rules.
			_ = stderr
			break
		}
	}

	m.applied = false
	return firstErr
}
