//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func configureChildProcess(cmd *exec.Cmd) {
	_ = cmd
}

func currentProcessCreationTime() (uint64, error) {
	// Only used for PID reuse safety checks in restore guard.
	// Non-Windows builds run without this check.
	return 0, nil
}

func waitForProcessExit(pid int, expectedStart uint64) error {
	_ = expectedStart
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}
	for {
		err := syscall.Kill(pid, 0)
		if err == nil || err == syscall.EPERM {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}
}
