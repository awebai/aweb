package awconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const requestFileIndexDir = ".requests"
const requestFileIndexGenerationFile = "generation.json"

type requestFileIndex struct {
	directory string
	files     fs.FS
	bindings  func() ([]requestFileBinding, error)
}

type requestFileIndexGeneration struct {
	Version             int   `json:"version"`
	DirectoryModifiedAt int64 `json:"directory_modified_at"`
}

type requestFileBinding struct {
	RequestID string `json:"request_id"`
	RecordID  string `json:"record_id"`
}

func requestFileIndexBindingName(requestID string) string {
	sum := sha256.Sum256([]byte(requestID))
	return hex.EncodeToString(sum[:]) + ".json"
}

// lookup returns an index binding without interpreting the operation's record.
// Its caller validates the binding against that record before using it.
func (index requestFileIndex) lookup(requestID string) (*requestFileBinding, error) {
	if err := index.ensure(); err != nil {
		return nil, err
	}
	data, err := fs.ReadFile(index.files, filepath.ToSlash(filepath.Join(requestFileIndexDir, requestFileIndexBindingName(requestID))))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var binding requestFileBinding
	if err := json.Unmarshal(data, &binding); err != nil {
		return nil, fmt.Errorf("invalid private request index: %w", err)
	}
	if binding.RequestID != requestID || binding.RecordID == "" {
		return nil, errors.New("private request index binding changed")
	}
	return &binding, nil
}

func (index requestFileIndex) ensure() error {
	if _, err := index.exists(); err != nil {
		return err
	}
	info, err := fs.Stat(index.files, ".")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	generationPath := filepath.ToSlash(filepath.Join(requestFileIndexDir, requestFileIndexGenerationFile))
	data, err := fs.ReadFile(index.files, generationPath)
	if err == nil {
		var generation requestFileIndexGeneration
		if err := json.Unmarshal(data, &generation); err != nil {
			return fmt.Errorf("invalid private request index generation: %w", err)
		}
		if generation.Version != 1 {
			return errors.New("unsupported private request index generation")
		}
		if generation.DirectoryModifiedAt == info.ModTime().UnixNano() {
			return nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return index.rebuild()
}

func (index requestFileIndex) rebuild() error {
	directory := filepath.Join(index.directory, requestFileIndexDir)
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("private request index must be a private directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return err
	}
	// Remove the completeness marker first. A crash during reconstruction must
	// never make a partial set of bindings look like a complete index.
	if err := os.Remove(filepath.Join(directory, requestFileIndexGenerationFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("unexpected directory in private request index")
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	records, err := index.bindings()
	if err != nil {
		return err
	}
	bindings := map[string]string{}
	for _, binding := range records {
		if prior, exists := bindings[binding.RequestID]; exists && prior != binding.RecordID {
			return errors.New("private request is bound to multiple records")
		}
		bindings[binding.RequestID] = binding.RecordID
		if err := index.writeBinding(binding); err != nil {
			return err
		}
	}
	return index.saveGeneration()
}

func (index requestFileIndex) writeBinding(binding requestFileBinding) error {
	data, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(index.directory, requestFileIndexDir, requestFileIndexBindingName(binding.RequestID)), data)
}

func (index requestFileIndex) saveGeneration() error {
	info, err := fs.Stat(index.files, ".")
	if err != nil {
		return err
	}
	data, err := json.Marshal(requestFileIndexGeneration{Version: 1, DirectoryModifiedAt: info.ModTime().UnixNano()})
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(index.directory, requestFileIndexDir, requestFileIndexGenerationFile), data)
}

type requestFileBindingChange struct{ Previous, Current *requestFileBinding }

// commit follows the operation's durable record write. If it fails, the old
// generation remains stale and the next lookup reconstructs from those records.
func (index requestFileIndex) commit(change requestFileBindingChange) error {
	if change.Previous != nil && (change.Current == nil || change.Previous.RequestID != change.Current.RequestID) {
		path := filepath.Join(index.directory, requestFileIndexDir, requestFileIndexBindingName(change.Previous.RequestID))
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if change.Current != nil {
		if err := index.writeBinding(*change.Current); err != nil {
			return err
		}
	}
	return index.saveGeneration()
}

func (index requestFileIndex) exists() (bool, error) {
	info, err := os.Lstat(filepath.Join(index.directory, requestFileIndexDir))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("private request index must be a directory, not a symlink")
	}
	return true, nil
}
