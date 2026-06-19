package pathpreflight

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Options struct {
	AllowTempAmbientSymlinkPrefix bool
}

func AllowTempAmbientSymlinkPrefix() Options {
	return Options{AllowTempAmbientSymlinkPrefix: true}
}

func PreflightDir(path, label string, opts Options) error {
	clean := filepath.Clean(path)
	if err := RejectSymlinkedExistingComponents(clean, label, opts); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s must not be a symlink", label, filepath.ToSlash(clean))
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %s must be a directory", label, filepath.ToSlash(clean))
	}
	return nil
}

func PreflightFile(path, label string, opts Options) error {
	clean := filepath.Clean(path)
	if err := RejectSymlinkedExistingComponents(filepath.Dir(clean), label, opts); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s must not be a symlink", label, filepath.ToSlash(clean))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s must be a regular file", label, filepath.ToSlash(clean))
	}
	return nil
}

func RejectSymlinkedExistingComponents(path, label string, opts Options) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	current := volume
	if filepath.IsAbs(clean) {
		current += string(filepath.Separator)
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if current == "" || current == string(filepath.Separator) || strings.HasSuffix(current, string(filepath.Separator)) {
			current += part
		} else {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if opts.AllowTempAmbientSymlinkPrefix && isAllowedAmbientSymlinkPrefix(current) {
				continue
			}
			return fmt.Errorf("%s parent %s must not be a symlink", label, filepath.ToSlash(current))
		}
		if !info.IsDir() {
			return fmt.Errorf("%s parent %s must be a directory", label, filepath.ToSlash(current))
		}
	}
	return nil
}

func isAllowedAmbientSymlinkPrefix(path string) bool {
	tempDir := filepath.Clean(os.TempDir())
	rel, err := filepath.Rel(filepath.Clean(path), tempDir)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."))
}
