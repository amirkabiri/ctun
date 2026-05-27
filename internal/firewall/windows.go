//go:build windows

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// windowsManager installs and removes ctun's Windows Firewall rules via
// the `netsh advfirewall firewall` CLI. It invokes the `netsh` binary
// directly via os/exec — there is no native Windows Filtering Platform
// (WFP) binding the minimal-dependency rule of the project would allow,
// and netsh ships with every supported Windows release.
//
// Apply emits exactly these invocations (replace <port> with the
// configured port; the rule name "ctun-<port>" is the cleanup tag):
//
//	Existence check (always run first):
//	  netsh advfirewall firewall show rule name=ctun-<port>
//
//	If the rule is absent, install it:
//	  netsh advfirewall firewall add rule name=ctun-<port> dir=in action=block protocol=TCP localport=<port>
//
// Cleanup emits:
//
//	netsh advfirewall firewall delete rule name=ctun-<port>
//
// Per the design doc and the T4.3 DoD, the Windows rule shape is simpler
// than the Linux iptables triplet: a single inbound block on the tunnel
// port suffices, because the Windows TCP/IP stack does not produce the
// same "stray SYN → RST" interference pattern Linux's conntrack-driven
// stack exhibits. The server-side / client-side distinction Apply takes
// is preserved (isServer is part of the Manager.Apply signature, shared
// across all backends), but the netsh backend installs the same rule
// regardless: an inbound block on the tunnel port is correct for both
// roles, since both server and client have pcap injecting traffic that
// the kernel must not "answer."
//
// Idempotency: netsh's `add rule` will silently install a duplicate rule
// with the same name if one already exists — Windows Firewall allows
// multiple rules to share a display name. Apply therefore runs `show
// rule` first and skips the add if a matching rule is present. The
// existence check distinguishes the two outcomes by exit code (0 =
// present, 1 = absent); when needed it also inspects stderr/stdout for
// the well-known "No rules match" diagnostic so a non-English Windows
// locale doesn't silently make us double-install.
//
// All exec calls capture stderr so failures produce a usable diagnostic
// message rather than a bare exit code. The "windows.go" file ships with
// build tag `windows`; on every other OS the firewall package selects
// either linux.go, darwin.go, or stub.go via their respective build tags.
type windowsManager struct {
	mu       sync.Mutex
	port     uint16
	isServer bool
	applied  bool

	// execCommand is exec.CommandContext by default; tests inject a fake
	// to assert argv shape without actually running netsh. Matches the
	// shape of linuxManager.execCommand and darwinManager.execCommand so
	// the three implementations read symmetrically.
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// NewWindows constructs a Manager backed by the system `netsh` binary.
// The returned Manager is safe for concurrent calls to Apply/Cleanup.
//
// On windows builds this overrides the stub returned by NewLinux on
// platforms without a real backend (the stub.go build tag is
// `!linux && !darwin && !windows`, so windows callers can pick the
// netsh backend explicitly via NewWindows while non-supported
// platforms still get the stub).
func NewWindows() Manager {
	return &windowsManager{
		execCommand: exec.CommandContext,
	}
}

// ruleName returns the netsh rule name embedded in every rule the
// windows backend installs: "ctun-<port>". Matches the comment tag the
// Linux backend uses (commentTag in firewall.go), so an operator who
// jumps between OSes sees the same identifier in `netsh advfirewall
// firewall show rule` as they would in `iptables-save | grep`.
//
// Defined locally rather than reusing commentTag so the windows.go file
// has zero non-build-tag-gated dependencies on firewall.go beyond the
// Manager interface and ErrNotImplemented. (commentTag is reachable from
// windows builds, but mirroring it locally keeps the netsh-specific
// rule-name semantics self-contained for the next maintainer.)
func ruleName(port uint16) string {
	return "ctun-" + strconv.FormatUint(uint64(port), 10)
}

// buildAddArgs returns the netsh argv for installing the inbound-block
// rule for the given port. Pure argv construction with no exec calls so
// it can be unit-tested on any platform (the windows backend's exec
// calls are tested separately, admin-gated, in windows_test.go).
//
// The returned slice is a full argv vector for `netsh` (i.e. element 0
// of the eventual exec argv array is "netsh", elided here).
//
// Note on quoting: we pass `name=ctun-<port>` and `localport=<port>` as
// individual argv elements without wrapping them in double-quotes. Under
// os/exec on Windows, argv is passed through to CreateProcessW; the
// double-quote literal Win32 callers often type at a cmd.exe prompt is
// the cmd shell's escape syntax, not netsh's. Passing the unquoted form
// here is correct and avoids a netsh parse error that would otherwise
// silently leave the rule uninstalled.
func buildAddArgs(port uint16) []string {
	name := ruleName(port)
	portStr := strconv.FormatUint(uint64(port), 10)
	return []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + name,
		"dir=in",
		"action=block",
		"protocol=TCP",
		"localport=" + portStr,
	}
}

// buildDeleteArgs returns the netsh argv for removing the rule for the
// given port. Pure argv construction; same testability rationale as
// buildAddArgs.
func buildDeleteArgs(port uint16) []string {
	return []string{
		"advfirewall", "firewall", "delete", "rule",
		"name=" + ruleName(port),
	}
}

// buildExistsArgs returns the netsh argv for checking whether a rule
// with the configured name is already present. Used by Apply to make
// installation idempotent: if `show rule` exits 0, a matching rule is
// already in place and Apply skips the add.
func buildExistsArgs(port uint16) []string {
	return []string{
		"advfirewall", "firewall", "show", "rule",
		"name=" + ruleName(port),
	}
}

// runNetsh invokes netsh with the given argv and returns (stdout,
// stderr, exit-code, error). Exit codes other than 0 are NOT folded into
// the error — callers that tolerate specific exit codes (e.g. 1 from
// `show rule` against an absent rule, or `delete rule` against an
// already-deleted rule) need to see the raw code. Matches the shape of
// linuxManager.runIPTables and darwinManager.runPfctl so the three
// implementations read symmetrically.
func (m *windowsManager) runNetsh(ctx context.Context, argv []string) (string, string, int, error) {
	cmd := m.execCommand(ctx, "netsh", argv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
			// An exit code is a legitimate result. Don't propagate the
			// exec error in that case; the caller decides.
			err = nil
		}
	}
	return stdout.String(), stderr.String(), exitCode, err
}

// ruleExists reports whether the netsh rule with the configured name is
// already installed. netsh `show rule name=<name>` exits 0 when at least
// one rule matches, exits 1 with the "No rules match the specified
// criteria." message when none match. We branch on exit code; if the
// exit code is ambiguous (anything other than 0 or 1) we additionally
// inspect stdout for the well-known "No rules match" string so a
// non-English locale doesn't silently mis-classify the result.
func (m *windowsManager) ruleExists(ctx context.Context, port uint16) (bool, error) {
	argv := buildExistsArgs(port)
	stdout, stderr, exitCode, err := m.runNetsh(ctx, argv)
	if err != nil {
		return false, fmt.Errorf("netsh %s failed: %w (stderr: %s)", strings.Join(argv, " "), err, strings.TrimSpace(stderr))
	}
	switch exitCode {
	case 0:
		return true, nil
	case 1:
		// netsh exits 1 when no rules match. This is the dominant absent
		// case on every Windows version we care about.
		return false, nil
	default:
		// Belt-and-braces: some netsh builds report absence via stdout
		// rather than exit code. Sniff for the canonical message; if
		// it's present, treat as absent. Otherwise surface the unusual
		// exit code as an error so an operator can investigate.
		if strings.Contains(stdout, "No rules match") {
			return false, nil
		}
		return false, fmt.Errorf("netsh %s exited %d (stdout: %s, stderr: %s)",
			strings.Join(argv, " "), exitCode,
			strings.TrimSpace(stdout), strings.TrimSpace(stderr))
	}
}

// Apply installs the netsh rule for the configured port. See the
// type-level comment block for the exact netsh invocations.
//
// Apply is idempotent: it runs `show rule` first and skips the add if a
// matching rule is already present. The `isServer` argument is part of
// the Manager.Apply contract but does not currently change the netsh
// rule shape (see the type-level comment for why).
func (m *windowsManager) Apply(port uint16, isServer bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Bound each netsh call so a stuck binary cannot wedge startup forever.
	// 5 s matches the Linux and darwin backends' budget and is well past
	// any healthy netsh invocation.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exists, err := m.ruleExists(ctx, port)
	if err != nil {
		return err
	}
	if !exists {
		addArgv := buildAddArgs(port)
		_, stderr, exitCode, err := m.runNetsh(ctx, addArgv)
		if err != nil {
			return fmt.Errorf("netsh %s failed: %w (stderr: %s)", strings.Join(addArgv, " "), err, strings.TrimSpace(stderr))
		}
		if exitCode != 0 {
			return fmt.Errorf("netsh %s exited %d (stderr: %s)", strings.Join(addArgv, " "), exitCode, strings.TrimSpace(stderr))
		}
	}

	m.port = port
	m.isServer = isServer
	m.applied = true
	return nil
}

// Cleanup removes the netsh rule previously installed by Apply. If Apply
// was never called (m.applied == false), Cleanup is a no-op so callers
// can `defer mgr.Cleanup()` unconditionally — matches the contract
// documented on Manager.Cleanup.
//
// `netsh advfirewall firewall delete rule name=<name>` removes every
// rule with the given display name. If no rule matches, netsh exits 1
// with "No rules match the specified criteria." — Cleanup tolerates
// that case silently so a panic-recovery double-Cleanup or a Cleanup
// against a partially-Applied state cannot escalate to a fatal error.
func (m *windowsManager) Cleanup() error {
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

	argv := buildDeleteArgs(m.port)
	stdout, stderr, exitCode, err := m.runNetsh(ctx, argv)

	var firstErr error
	if err != nil {
		firstErr = fmt.Errorf("netsh %s failed: %w (stderr: %s)", strings.Join(argv, " "), err, strings.TrimSpace(stderr))
	} else if exitCode != 0 {
		// Tolerate "no such rule" — that's the expected exit when the
		// rule was already removed (e.g. by a previous Cleanup, or by an
		// operator running netsh manually between Apply and Cleanup).
		// netsh emits the canonical "No rules match" string in this case
		// on every locale we know of; if some future Windows ships a
		// locale where the string differs, the exit code alone is not a
		// trustworthy discriminator and we'd rather under-report than
		// over-report cleanup failures.
		if !strings.Contains(stdout, "No rules match") && !strings.Contains(stderr, "No rules match") {
			firstErr = fmt.Errorf("netsh %s exited %d (stdout: %s, stderr: %s)",
				strings.Join(argv, " "), exitCode,
				strings.TrimSpace(stdout), strings.TrimSpace(stderr))
		}
	}

	m.applied = false
	return firstErr
}
