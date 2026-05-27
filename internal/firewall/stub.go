//go:build !linux && !darwin && !windows

package firewall

// stubManager is the Manager returned by NewLinux on every platform that
// does not yet have a real implementation. Apply and Cleanup return
// ErrNotImplemented so callers can branch on errors.Is — typically
// printing a "manual recipe required" message and continuing without
// rules installed.
//
// T4.2 (macOS / pfctl) and T4.3 (Windows / netsh) have shipped — darwin
// and windows builds get their real implementations from darwin.go and
// windows.go respectively, not this stub. The build tag at the top of
// this file excludes linux, darwin, and windows; remaining platforms
// (FreeBSD, OpenBSD, illumos, etc.) still fall through to the stub here.
// Tighten the tag again when each remaining platform gains a real backend.
type stubManager struct{}

// NewLinux on an unsupported build returns a stub. The name is preserved
// (and not, say, `NewStub`) so callers can continue using the same
// constructor on every OS without build-tag dispatch at the call site.
// T4.2 added NewDarwin in darwin.go and T4.3 added NewWindows in
// windows.go (each selected on its own build tag). Until those
// constructors are wired into cmd/ in T4.4, callers just call NewLinux
// and get back the per-platform Manager.
func NewLinux() Manager {
	return &stubManager{}
}

func (s *stubManager) Apply(port uint16, isServer bool) error {
	return ErrNotImplemented
}

func (s *stubManager) Cleanup() error {
	return ErrNotImplemented
}
