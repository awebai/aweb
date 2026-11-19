package awid

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
)

// ScanKeysForPublicKey searches keysDir (and keysDir/rotated/) for a private
// key whose derived public key matches target. Returns the path to the private
// key file, or empty string if not found.
func ScanKeysForPublicKey(keysDir string, target ed25519.PublicKey) (string, error) {
	dirs := []string{keysDir}
	rotatedDir := filepath.Join(keysDir, "rotated")
	if info, err := os.Stat(rotatedDir); err == nil && info.IsDir() {
		dirs = append(dirs, rotatedDir)
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".key") {
				continue
			}
			path := filepath.Join(dir, name)
			priv, err := LoadSigningKey(path)
			if err != nil {
				continue
			}
			pub := priv.Public().(ed25519.PublicKey)
			if pub.Equal(target) {
				return path, nil
			}
		}
	}

	return "", nil
}
