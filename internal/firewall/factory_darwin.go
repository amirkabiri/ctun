//go:build darwin

package firewall

// newCurrentOSManager returns the darwin pfctl-backed Manager. The
// build-tag-gated sibling files (factory_linux.go, factory_windows.go,
// factory_other.go) provide the per-OS counterparts so NewForCurrentOS
// in factory.go compiles on every supported build.
func newCurrentOSManager() Manager {
	return NewDarwin()
}
