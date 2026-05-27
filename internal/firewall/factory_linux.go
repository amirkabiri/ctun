//go:build linux

package firewall

// newCurrentOSManager returns the Linux iptables-backed Manager. The
// build-tag-gated sibling files (factory_darwin.go, factory_windows.go,
// factory_other.go) provide the per-OS counterparts so NewForCurrentOS
// in factory.go compiles on every supported build.
func newCurrentOSManager() Manager {
	return NewLinux()
}
