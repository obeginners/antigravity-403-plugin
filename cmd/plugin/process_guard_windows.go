//go:build windows

package main

import (
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func configureChildProcess(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

func waitForProcessExit(pid int, expectedStart uint64) error {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Process already gone.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil
		}
		return err
	}
	defer windows.CloseHandle(handle)
	if expectedStart > 0 {
		currentStart, errStart := processCreationTimeFromHandle(handle)
		if errStart == nil && currentStart != expectedStart {
			// PID has been reused by another process; treat parent as exited.
			return nil
		}
	}
	_, err = windows.WaitForSingleObject(handle, windows.INFINITE)
	return err
}

func currentProcessCreationTime() (uint64, error) {
	handle := windows.CurrentProcess()
	return processCreationTimeFromHandle(handle)
}

func processCreationTimeFromHandle(handle windows.Handle) (uint64, error) {
	var created windows.Filetime
	var exited windows.Filetime
	var kernel windows.Filetime
	var user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return (uint64(created.HighDateTime) << 32) | uint64(created.LowDateTime), nil
}
