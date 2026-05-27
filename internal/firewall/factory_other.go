//go:build !linux && !darwin && !windows

package firewall

// newCurrentOSManager returns the stub Manager on platforms without a
// real firewall backend (today: FreeBSD, OpenBSD, illumos, ...). The
// stub's Apply / Cleanup return ErrNotImplemented; callers of
// NewForCurrentOS are expected to branch on errors.Is(err,
// ErrNotImplemented) and log a "manual rules required" warning.
//
// The build-tag-gated sibling files (factory_linux.go,
// factory_darwin.go, factory_windows.go) provide the per-OS
// counterparts. NewLinux on a !linux && !darwin && !windows build
// resolves to the stub defined in stub.go.
func newCurrentOSManager() Manager {
	return NewLinux()
}
