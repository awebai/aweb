//go:build !windows

package main

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func listenCustodySocket(socketPath string) (net.Listener, error) {
	oldUmask := syscall.Umask(0o077)
	ln, err := net.Listen("unix", socketPath)
	syscall.Umask(oldUmask)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

func isStaleCustodySocketError(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOTSOCK)
}
