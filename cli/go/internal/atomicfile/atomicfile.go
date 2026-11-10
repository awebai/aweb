// Package atomicfile replaces a file so that a reader, or a host that crashes
// at any moment, finds either the complete previous content or the complete
// replacement, and so that a completed write survives a crash.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Options selects how Write stores a file. Mode is required; the zero value of
// every other field gives a plain replacing write into an existing directory.
type Options struct {
	// Mode is the exact permission of the written file, whatever the umask.
	Mode os.FileMode

	// ParentMode, when non-zero, creates missing parent directories with that
	// mode (subject to the umask). When zero a missing parent is an error.
	ParentMode os.FileMode

	// Exclusive makes the write fail with an error matching os.ErrExist when
	// anything, including a dangling symlink, already occupies the
	// destination. The occupant is left untouched.
	Exclusive bool

	// TempName lets one serialized writer reuse a private temp file name
	// instead of leaving a new name in the directory cache on every write.
	// When it points at an empty string, Write stores the unique name it
	// chose there. When it points at a name, Write creates exactly that file,
	// and refuses with an error matching os.ErrExist, removing nothing, if a
	// file or symlink already has the name. Two writers must never share one.
	TempName *string

	// BeforeCommit, when set, runs after the temp file is complete, synced
	// and closed, and before it takes the destination's name.
	BeforeCommit func()
}

// Write replaces path with data. The parent directory must exist.
//
// The data goes to a temp file in the same directory as path, created with
// O_EXCL under a unique ".tmp." name. The temp file is created with mode 0600
// and set to exactly mode through its open descriptor before any data is
// written, so the result does not depend on the umask and the data is never
// readable through a mode wider than the one requested. The temp file is
// written in full, synced and closed, then renamed over path, and then the
// parent directory is synced so the rename itself survives a host crash.
//
// A failure before the rename removes the temp file and leaves path exactly as
// it was. A failure of the directory sync is reported although path already
// holds the new content: the write is complete but not known to be durable.
// The rename replaces a symlink at path; it does not write through it.
//
// Every error names path. The directory sync is skipped on Windows and on a
// filesystem that answers that it cannot sync a directory.
func Write(path string, data []byte, mode os.FileMode) error {
	return Options{Mode: mode}.Write(path, data)
}

// WriteExclusive creates path with data only when nothing occupies path, and
// otherwise fails with an error matching os.ErrExist, leaving the occupant
// untouched. It gives the same guarantees as Write, with the temp file hard
// linked to path instead of renamed over it, so the destination appears
// complete or not at all and two concurrent writers cannot both succeed.
func WriteExclusive(path string, data []byte, mode os.FileMode) error {
	return Options{Mode: mode, Exclusive: true}.Write(path, data)
}

// Write stores data at path as described by Write and WriteExclusive, with the
// variations the options select.
func (o Options) Write(path string, data []byte) error {
	if err := o.write(path, data); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	return nil
}

func (o Options) write(path string, data []byte) error {
	dir := filepath.Dir(path)
	if o.ParentMode != 0 {
		if err := os.MkdirAll(dir, o.ParentMode); err != nil {
			return err
		}
	}

	tmp, err := o.createTemp(dir)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Only a file this call created is ever removed.
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()

	if err := fill(tmp, data, o.Mode); err != nil {
		return err
	}
	if o.BeforeCommit != nil {
		o.BeforeCommit()
	}

	if o.Exclusive {
		if err := os.Link(tmpName, path); err != nil {
			return err
		}
		// A second name for the content must not outlive the write.
		if err := os.Remove(tmpName); err != nil {
			return err
		}
	} else if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	removeTemp = false

	if err := SyncDir(dir); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func (o Options) createTemp(dir string) (*os.File, error) {
	if o.TempName != nil && *o.TempName != "" {
		return os.OpenFile(*o.TempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
	tmp, err := os.CreateTemp(dir, ".tmp.*")
	if err == nil && o.TempName != nil {
		*o.TempName = tmp.Name()
	}
	return tmp, err
}

// fill sets the mode, writes and syncs data, and closes the file.
func fill(file *os.File, data []byte, mode os.FileMode) error {
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
