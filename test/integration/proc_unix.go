//go:build !windows

package integration

import "syscall"

// newProcAttr returns SysProcAttr that puts the child in its own process group
// so that a SIGTERM aimed at the child does not propagate back to the parent
// (`go test`) via the controlling terminal, and so that signals can later be
// broadcast to the whole subprocess tree if needed.
func newProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
