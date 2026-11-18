//go:build windows

package wake

// Access to the Windows profile/state directory is governed by its ACL.
func checkWakeDirectory(path string) error { return nil }
