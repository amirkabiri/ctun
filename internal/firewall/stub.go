//go:build !linux && !darwin

package firewall

// stubManager is the Manager returned by NewLinux on every platform that
// does not yet have a real implementation. Apply and Cleanup return
// ErrNotImplemented so callers can branch on errors.Is — typically
// printing a "manual recipe required" message and continuing without
// rules installed.
//
// T4.2 (macOS / pfctl) has been shipped — darwin builds get the real
// implementation from darwin.go, not this stub. T4.3 (Windows / netsh)
// will replace the Windows path next; until then Windows still falls
// through to the stub here. The build tag at the top of this file
// excludes both linux and darwin; tighten it again when each remaining
// platform gains a real backend.
type stubManager struct{}

// NewLinux on an unsupported build returns a stub. The name is preserved
// (and not, say, `NewStub`) so callers can continue using the same
// constructor on every OS without build-tag dispatch at the call site.
// T4.2 added NewDarwin in darwin.go (selected on macOS via its own
// build tag); T4.3 will add NewWindows. Until those constructors are
// wired into cmd/ in T4.4, callers just call NewLinux and get back the
// per-platform Manager.
func NewLinux() Manager {
	return &stubManager{}
}

func (s *stubManager) Apply(port uint16, isServer bool) error {
	return ErrNotImplemented
}

func (s *stubManager) Cleanup() error {
	return ErrNotImplemented
}
