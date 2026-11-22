//go:build windows

package wake

import "os"

// Access to Windows state and private snapshot directories is governed by ACLs.
func warnWakeDirectory(path string)                  {}
func checkRunnerSnapshotDirectory(path string) error { return nil }
func checkRunnerSnapshotParent(path string) error    { return nil }

// Windows stale cleanup needs an ACL owner check; never infer ownership from a
// temporary path. Normal child-exit cleanup remains available.
func runnerSnapshotOwnedByCurrentUser(info os.FileInfo) (bool, error) { return false, nil }
