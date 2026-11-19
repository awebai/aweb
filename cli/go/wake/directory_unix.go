//go:build !windows

package wake

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
)

var wakeDirectoryWarnings sync.Map

type wakeDirectoryPermissions struct {
	Path  string
	Owner uint32
	Mode  os.FileMode
}

func inspectWakeDirectory(path string) (wakeDirectoryPermissions, error) {
	info, err := os.Stat(path)
	if err != nil {
		return wakeDirectoryPermissions{}, fmt.Errorf("inspect wake directory %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok {
		return wakeDirectoryPermissions{}, fmt.Errorf("cannot inspect wake directory %s. Select a directory with --state-dir and retry aw wake.", path)
	}
	return wakeDirectoryPermissions{Path: path, Owner: stat.Uid, Mode: info.Mode()}, nil
}

func (directory wakeDirectoryPermissions) repairAdvice() string {
	var commands []string
	quotedPath := "'" + strings.ReplaceAll(directory.Path, "'", "'\\''") + "'"
	if directory.Owner != uint32(os.Geteuid()) {
		commands = append(commands, fmt.Sprintf("sudo chown %d %s", os.Geteuid(), quotedPath))
	}
	if directory.Mode.Perm()&0o022 != 0 {
		commands = append(commands, "chmod go-w "+quotedPath)
	}
	if directory.Mode.Perm()&0o200 == 0 {
		commands = append(commands, "chmod u+w "+quotedPath)
	}
	return strings.Join(commands, "; ")
}

// warnWakeDirectory implements docs/wake-runner-integrity.md:8-11.
// Existing state layouts remain usable; each affected path warns once per process.
func warnWakeDirectory(path string) {
	directory, err := inspectWakeDirectory(path)
	if err == nil && directory.repairAdvice() == "" {
		return
	}
	if _, warned := wakeDirectoryWarnings.LoadOrStore(path, struct{}{}); warned {
		return
	}
	if err != nil {
		log.Printf("Warning: %v. Check directory access before running the wake broker.", err)
		return
	}
	log.Printf("Warning: wake state directory %s is shared or owned by uid %d. To make this directory private, run: %s. State operations remain available; runner execution uses a separate private snapshot.", path, directory.Owner, directory.repairAdvice())
}

// writableByAnotherUser implements docs/wake-runner-integrity.md:13-16.
// Root already controls the process; root ownership alone adds no cache writer.
func (directory wakeDirectoryPermissions) writableByAnotherUser() bool {
	return directory.Mode.Perm()&0o022 != 0 || (directory.Owner != uint32(os.Geteuid()) && directory.Owner != 0)
}

func checkRunnerSnapshotDirectory(path string) error {
	directory, err := inspectWakeDirectory(path)
	if err != nil {
		return err
	}
	if directory.writableByAnotherUser() {
		return fmt.Errorf("unsafe private runner directory %s: another user can replace runner bytes. Run %s, then retry aw wake.", path, directory.repairAdvice())
	}
	return nil
}

func checkRunnerSnapshotParent(path string) error {
	directory, err := inspectWakeDirectory(path)
	if err != nil {
		return err
	}
	foreignOwner := directory.Owner != 0 && directory.Owner != uint32(os.Geteuid())
	if foreignOwner || (directory.Mode.Perm()&0o022 != 0 && directory.Mode&os.ModeSticky == 0) {
		return fmt.Errorf("unsafe system temporary directory %s. Ask the system administrator to restore its ownership and sticky permissions, then retry aw wake.", path)
	}
	return nil
}

// Only the effective user's own directories may be removed by stale cleanup.
func runnerSnapshotOwnedByCurrentUser(info os.FileInfo) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("cannot inspect runner snapshot owner")
	}
	return stat.Uid == uint32(os.Geteuid()), nil
}
