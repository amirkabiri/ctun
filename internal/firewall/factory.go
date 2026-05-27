package firewall

// NewForCurrentOS returns the Manager appropriate for the host operating
// system. T4.4 introduces this as the canonical constructor for callers
// in cmd/run/ that don't want a per-OS switch at every call site.
//
// The mapping is:
//
//   - linux   → NewLinux()    (real iptables-backed implementation)
//   - darwin  → NewDarwin()   (real pfctl-backed implementation)
//   - windows → NewWindows()  (real netsh-backed implementation)
//   - other   → stub (NewLinux on stubbed builds returns a stub whose
//     Apply / Cleanup return ErrNotImplemented). Callers are expected
//     to branch on errors.Is(err, ErrNotImplemented) and log a "manual
//     rules required" warning before continuing.
//
// The dispatch happens at compile time via build-tagged sibling files
// (factory_linux.go / factory_darwin.go / factory_windows.go /
// factory_other.go) each providing a single newCurrentOSManager() that
// resolves to the right constructor on the build's GOOS. This avoids
// naming NewLinux / NewDarwin / NewWindows directly from the
// no-build-tag file (which would not compile across all OSes).
func NewForCurrentOS() Manager {
	return newCurrentOSManager()
}
