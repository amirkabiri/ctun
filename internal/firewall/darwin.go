//go:build darwin

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// darwinManager installs and removes ctun's pf rules on macOS. It invokes
// the `pfctl` binary directly via os/exec — there is no native pf API the
// minimal-dependency rule of the project would allow, and pfctl is shipped
// with every macOS release.
//
// Apply writes a tempfile containing the anchor body, then loads it into a
// named anchor `ctun.<port>` with:
//
//	pfctl -a ctun.<port> -f <tmpfile>
//
// pfctl replaces the anchor's ruleset wholesale on each `-f` call, so
// re-Apply with the same args is naturally idempotent — no duplicate rules
// accumulate, and no `-C`-style check is required (unlike the Linux backend).
// The tempfile path is stable per darwinManager instance (one path per
// configured port), so a re-Apply overwrites the same file rather than
// littering /tmp.
//
// Server side (isServer=true): the anchor contains two `block drop` rules
// that silently drop kernel-generated traffic to/from the tunnel port so
// the kernel cannot interfere with the synthetic flow ctun injects via pcap.
// We use `block drop` rather than `block return-rst`: the whole point of
// these rules is to *prevent* RSTs, so generating them would be paradoxical.
// Design-doc §12 sketches the macOS rules in less detail than the Linux
// rules; the brief for T4.2 explicitly defaults to `block drop` and that
// is what we ship.
//
// Client side (isServer=false): the anchor body is empty. The client does
// not listen on the tunnel port — it only injects outbound SYNs and reads
// inbound packets via pcap — so the kernel has no traffic to interfere
// with on the client side. The anchor still gets registered (with an empty
// ruleset) so that Cleanup's `pfctl -a ctun.<port> -F all` has a target,
// and so the Apply/Cleanup shape is symmetric with the server side.
//
// Cleanup flushes the anchor (`pfctl -a ctun.<port> -F all`) and removes
// the tempfile. Flushing an absent anchor is a no-op in pfctl, so Cleanup
// tolerates the "never Applied" case without an error — required for
// panic-recovery callers that `defer mgr.Cleanup()` before Apply has run.
//
// All exec calls capture stderr so failures produce a usable diagnostic
// message rather than a bare exit code.
type darwinManager struct {
	mu       sync.Mutex
	port     uint16
	isServer bool
	applied  bool

	// tmpfilePath is the path to the anchor body tempfile on disk. It is
	// derived from the port on first Apply (so Apply twice with the same
	// port reuses the file rather than leaking new ones) and cleared by
	// Cleanup. Exposed via a method for tests; not part of the public API.
	tmpfilePath string

	// execCommand is exec.CommandContext by default; tests inject a fake
	// to assert argv shape without actually running pfctl.
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// NewDarwin constructs a Manager backed by the system `pfctl` binary.
// The returned Manager is safe for concurrent calls to Apply/Cleanup.
//
// On darwin builds this override the stub returned by NewLinux on
// non-Linux platforms (the stub.go build tag is `!linux && !darwin`, so
// macOS callers can pick the darwin backend explicitly via NewDarwin
// while non-supported platforms still get the stub).
func NewDarwin() Manager {
	return &darwinManager{
		execCommand: exec.CommandContext,
	}
}

// anchorName returns the pf anchor name for the given port: "ctun.<port>".
// pf anchor names use dot-separated segments rather than dashes (dashes are
// permitted but the convention is dots), so we follow that here.
func anchorName(port uint16) string {
	return "ctun." + strconv.FormatUint(uint64(port), 10)
}

// tmpfilePathFor returns the stable tempfile path used to stage the anchor
// body for the given port. Stable per port so that a re-Apply overwrites
// the same file rather than leaving stale fragments in os.TempDir().
func tmpfilePathFor(port uint16) string {
	return filepath.Join(os.TempDir(), "ctun-"+strconv.FormatUint(uint64(port), 10)+".anchor")
}

// buildAnchorBody returns the pf ruleset body that gets written to the
// anchor tempfile and loaded with `pfctl -a <anchor> -f <file>`.
//
// Server side: two `block drop` rules that silently drop traffic the
// kernel would otherwise emit on the tunnel port (kernel-generated SYN-ACKs
// to inbound SYNs that don't match a listening socket, and any
// kernel-generated RSTs). `block drop` is the silent variant (no response
// packet generated); `block return-rst` would be paradoxical since we are
// trying to suppress RSTs in the first place.
//
// Client side: empty body. The anchor still gets loaded (with an empty
// ruleset) so Cleanup has a target and the lifecycle is symmetric with
// the server side; this is a documented design choice in the T4.2 brief.
//
// Lives without a build tag inside darwin.go because every caller is also
// darwin-gated; this is a helper for the darwin backend, not a
// cross-platform utility.
func buildAnchorBody(port uint16, isServer bool) string {
	if !isServer {
		// Empty anchor body. pfctl will register the anchor with no rules,
		// which is exactly what we want on the client: the kernel doesn't
		// emit problematic packets on the tunnel port on a non-listening
		// client, so there is nothing to block.
		return ""
	}
	portStr := strconv.FormatUint(uint64(port), 10)
	// Two rules: one for the inbound direction (kernel would otherwise
	// answer a stray SYN with SYN-ACK or RST), one for the outbound
	// direction (kernel might generate RSTs in response to packets that
	// don't match an established socket).
	//
	// `block drop` is silent — no RST, no ICMP, just discard.
	// `quick` makes the rule terminal so later rules in pf.conf cannot
	// override it; without `quick` the last matching rule wins, which
	// would let a permissive global rule undo our block.
	return "" +
		"block drop quick proto tcp from any to any port " + portStr + "\n" +
		"block drop quick proto tcp from any port " + portStr + " to any\n"
}

// runPfctl invokes pfctl with the given argv and returns (stdout, stderr,
// exit-code, error). Exit codes other than 0 are NOT folded into the error
// — callers that tolerate specific exit codes need to see the raw code.
// Matches the shape of linuxManager.runIPTables so the two implementations
// read symmetrically.
func (m *darwinManager) runPfctl(ctx context.Context, argv []string) (string, string, int, error) {
	cmd := m.execCommand(ctx, "pfctl", argv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
			err = nil
		}
	}
	return stdout.String(), stderr.String(), exitCode, err
}

// Apply installs the rule set for the configured port. See the type-level
// comment for the exact pfctl invocations and rule shape.
//
// pfctl's `-a <anchor> -f <file>` replaces the anchor's ruleset wholesale,
// so calling Apply twice with the same args naturally produces the same
// state — no `-C`-style precheck is needed for idempotency.
func (m *darwinManager) Apply(port uint16, isServer bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tmpPath := tmpfilePathFor(port)
	body := buildAnchorBody(port, isServer)

	// Write the anchor body to the stable tempfile path. We use 0600
	// because the file contains nothing sensitive but there is no reason
	// for it to be world-readable, and the conservative default keeps a
	// security review from flagging it. WriteFile truncates an existing
	// file so a re-Apply overwrites cleanly.
	if err := os.WriteFile(tmpPath, []byte(body), 0600); err != nil {
		return fmt.Errorf("firewall: write anchor body to %s: %w", tmpPath, err)
	}

	// Bound the pfctl call so a stuck binary cannot wedge startup forever.
	// 5 s matches the Linux backend's budget and is well past any healthy
	// pfctl invocation.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	argv := []string{"-a", anchorName(port), "-f", tmpPath}
	_, stderr, exitCode, err := m.runPfctl(ctx, argv)
	if err != nil {
		// Remove the tempfile on failure so we don't leak it. The Apply
		// failed, so we don't want to mark the manager as applied; the
		// tempfile would otherwise dangle until Cleanup that may never
		// come (the caller may decide not to Cleanup after a failed Apply).
		_ = os.Remove(tmpPath)
		return fmt.Errorf("pfctl %s failed: %w (stderr: %s)", strings.Join(argv, " "), err, strings.TrimSpace(stderr))
	}
	if exitCode != 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("pfctl %s exited %d (stderr: %s)", strings.Join(argv, " "), exitCode, strings.TrimSpace(stderr))
	}

	m.port = port
	m.isServer = isServer
	m.tmpfilePath = tmpPath
	m.applied = true
	return nil
}

// Cleanup flushes the anchor and removes the tempfile. If Apply was never
// called (m.applied == false), Cleanup is a no-op so callers can
// `defer mgr.Cleanup()` unconditionally — matches the contract documented
// on Manager.Cleanup.
//
// `pfctl -a <anchor> -F all` flushes the anchor's ruleset. Flushing an
// anchor that doesn't exist is a no-op (pfctl prints a notice but exits 0),
// so Cleanup tolerates duplicate calls.
func (m *darwinManager) Cleanup() error {
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

	argv := []string{"-a", anchorName(m.port), "-F", "all"}
	_, stderr, exitCode, err := m.runPfctl(ctx, argv)
	if err != nil {
		firstErr = fmt.Errorf("pfctl %s failed: %w (stderr: %s)", strings.Join(argv, " "), err, strings.TrimSpace(stderr))
	} else if exitCode != 0 {
		// Non-zero exit on flush is tolerated: pfctl reports "No ALTQ
		// support in kernel" or similar advisory exits as non-zero on
		// some macOS versions even when the flush itself succeeded. We
		// only escalate if stderr mentions an actual error keyword.
		trimmed := strings.TrimSpace(stderr)
		if trimmed != "" && !isBenignPfctlStderr(trimmed) {
			firstErr = fmt.Errorf("pfctl %s exited %d (stderr: %s)", strings.Join(argv, " "), exitCode, trimmed)
		}
	}

	// Remove the tempfile if it still exists. os.Remove returns an error
	// only if the file existed and could not be removed; an absent file
	// (e.g. someone manually cleared os.TempDir()) is not an error from
	// our perspective. We check IsNotExist to ignore that case.
	if m.tmpfilePath != "" {
		if err := os.Remove(m.tmpfilePath); err != nil && !os.IsNotExist(err) {
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall: remove anchor tempfile %s: %w", m.tmpfilePath, err)
			}
		}
	}

	m.applied = false
	m.tmpfilePath = ""
	return firstErr
}

// isBenignPfctlStderr reports whether a non-zero-exit pfctl stderr message
// is a known advisory (ALTQ support, "pf enabled", etc.) that does not
// indicate an actual failure to perform the requested operation. pfctl
// historically prints these on stderr even on success.
//
// The list is intentionally narrow; if a real error mode produces unmatched
// stderr, Cleanup will surface it as expected.
func isBenignPfctlStderr(s string) bool {
	benign := []string{
		"No ALTQ support in kernel",
		"ALTQ support",
		"pf enabled",
		"pf already enabled",
	}
	for _, needle := range benign {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
