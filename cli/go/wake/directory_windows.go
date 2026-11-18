//go:build windows

package wake

// Access to Windows state and executable-cache directories is governed by ACLs.
func warnWakeDirectory(path string)               {}
func checkRunnerCacheDirectory(path string) error { return nil }
