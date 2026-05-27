//go:build windows

package integration

import "syscall"

// newProcAttr is a no-op on Windows; the integration test is gated by
// `os.Getuid() != 0`, which is never true on Windows, so this path only
// has to compile, not actually run.
func newProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
