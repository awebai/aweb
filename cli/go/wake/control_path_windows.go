//go:build windows

package wake

import "errors"

func prepareControlSocket(path string) error {
	return checkControlSocket(path)
}

func checkControlSocket(string) error {
	return errors.New("wake control sockets are unsupported on Windows")
}

// Windows state access is governed by ACLs.
func checkWakeControlDirectory(string, bool) error { return nil }
