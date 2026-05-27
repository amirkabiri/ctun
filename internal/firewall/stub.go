//go:build !linux

package firewall

// stubManager is the Manager returned by NewLinux on every platform that
// does not yet have a real implementation. Apply and Cleanup return
// ErrNotImplemented so callers can branch on errors.Is — typically
// printing a "manual recipe required" message and continuing without
// rules installed.
//
// T4.2 (macOS / pfctl) and T4.3 (Windows / netsh) will replace this stub
// with platform-narrow implementations. Each adds a file with its own
// build tag (e.g. `//go:build darwin`, `//go:build windows`) and tightens
// this file's tag accordingly so the stub remains the catch-all for
// truly-unsupported platforms.
type stubManager struct{}

// NewLinux on a non-Linux build returns a stub. The name is preserved (and
// not, say, `NewStub`) so callers can continue using the same constructor
// on every OS without build-tag dispatch at the call site. T4.2/T4.3 will
// add NewDarwin/NewWindows constructors when needed; until then callers
// just call NewLinux and get back the per-platform Manager.
func NewLinux() Manager {
	return &stubManager{}
}

func (s *stubManager) Apply(port uint16, isServer bool) error {
	return ErrNotImplemented
}

func (s *stubManager) Cleanup() error {
	return ErrNotImplemented
}
