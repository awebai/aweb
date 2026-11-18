//go:build windows

package wake

import "os"

// Access to Windows state and private snapshot directories is governed by ACLs.
func warnWakeDirectory(path string)                  {}
func checkRunnerSnapshotDirectory(path string) error { return nil }
func checkRunnerSnapshotParent(path string) error    { return nil }
func runnerSnapshotRoot() string                     { return os.TempDir() }
