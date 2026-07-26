// Package crashtest provides an inert-by-default process checkpoint used by
// real-binary SIGKILL recovery tests. It is internal test instrumentation, not
// production control flow.
package crashtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const protocol = "aweb-internal-rotation-crash-test-v1"

const (
	protocolEnv     = "AWEB_INTERNAL_ROTATION_CRASH_TEST_PROTOCOL"
	pointEnv        = "AWEB_INTERNAL_ROTATION_CRASH_TEST_POINT"
	pathContainsEnv = "AWEB_INTERNAL_ROTATION_CRASH_TEST_PATH_CONTAINS"
	readyFDEnv      = "AWEB_INTERNAL_ROTATION_CRASH_TEST_READY_FD"
	controlFDEnv    = "AWEB_INTERNAL_ROTATION_CRASH_TEST_CONTROL_FD"
)

// Checkpoint notifies an inherited ready pipe and blocks on an inherited
// control pipe only when the complete versioned test capability is present.
// With the capability unset, malformed, or incomplete it returns immediately.
func Checkpoint(point string, path ...string) {
	if os.Getenv(protocolEnv) != protocol || os.Getenv(pointEnv) != point {
		return
	}
	selector := filepath.ToSlash(strings.TrimSpace(os.Getenv(pathContainsEnv)))
	if selector != "" {
		if len(path) == 0 || !strings.Contains(filepath.ToSlash(path[0]), selector) {
			return
		}
	}
	readyFD, readyErr := inheritedFD(readyFDEnv)
	controlFD, controlErr := inheritedFD(controlFDEnv)
	if readyErr != nil || controlErr != nil || readyFD == controlFD {
		return
	}
	ready := os.NewFile(uintptr(readyFD), "rotation-crash-ready")
	control := os.NewFile(uintptr(controlFD), "rotation-crash-control")
	if ready == nil || control == nil {
		return
	}
	defer ready.Close()
	defer control.Close()
	if _, err := fmt.Fprintln(ready, point); err != nil {
		return
	}
	var release [1]byte
	_, _ = control.Read(release[:])
}

func inheritedFD(name string) (int, error) {
	fd, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || fd < 3 {
		return 0, fmt.Errorf("invalid inherited file descriptor")
	}
	return fd, nil
}
