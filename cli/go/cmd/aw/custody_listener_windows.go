//go:build windows

package main

import (
	"errors"
	"net"
	"os"
)

func listenCustodySocket(socketPath string) (net.Listener, error) {
	return nil, usageError("custody_unsupported: local custody uses owner-only Unix sockets and is not supported on Windows")
}

func isStaleCustodySocketError(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
