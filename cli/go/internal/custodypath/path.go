// Package custodypath locates long-root custody sockets in a private user directory.
package custodypath

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func RuntimeDir() string {
	base := "/tmp"
	if runtime.GOOS == "darwin" {
		base = "/private/tmp"
	}
	return filepath.Join(base, fmt.Sprintf("aw-custody-%d", os.Geteuid()))
}

func Default(root string) string {
	root = filepath.Clean(root)
	if absolute, err := filepath.Abs(root); err == nil {
		root = absolute
	}
	if canonical, err := filepath.EvalSymlinks(root); err == nil {
		root = canonical
	}
	legacy := filepath.Join(root, "run", "custody.sock")
	// Use the strictest supported Unix limit on every platform.
	if len(legacy) <= 103 {
		return legacy
	}
	digest := sha256.Sum256([]byte(root))
	return filepath.Join(RuntimeDir(), fmt.Sprintf("%x.sock", digest[:20]))
}

func IsRuntime(socket string) bool { return filepath.Dir(filepath.Clean(socket)) == RuntimeDir() }
