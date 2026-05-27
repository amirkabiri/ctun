//go:build windows

package firewall

// newCurrentOSManager returns the Windows netsh-backed Manager. The
// build-tag-gated sibling files (factory_linux.go, factory_darwin.go,
// factory_other.go) provide the per-OS counterparts so NewForCurrentOS
// in factory.go compiles on every supported build.
func newCurrentOSManager() Manager {
	return NewWindows()
}
