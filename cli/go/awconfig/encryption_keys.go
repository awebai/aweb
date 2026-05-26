package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type EncryptionKeyState struct {
	ActiveKeyID string                `yaml:"active_key_id,omitempty"`
	Keys        []EncryptionKeyRecord `yaml:"keys,omitempty"`
}

type EncryptionKeyRecord struct {
	KeyID          string `yaml:"key_id"`
	PublicKey      string `yaml:"public_key"`
	PrivateKeyPath string `yaml:"private_key_path"`
	AssertionPath  string `yaml:"assertion_path,omitempty"`
	CreatedAt      string `yaml:"created_at"`
	NotBefore      string `yaml:"not_before"`
	ExpiresAt      string `yaml:"expires_at"`
	PublishedAt    string `yaml:"published_at,omitempty"`
}

func DefaultWorktreeEncryptionStateRelativePath() string {
	return filepath.Join(".aw", "encryption.yaml")
}

func DefaultWorktreeEncryptionKeysRelativeDir() string {
	return filepath.Join(".aw", "encryption-keys")
}

func WorktreeEncryptionStatePath(root string) string {
	return filepath.Join(filepath.Clean(root), DefaultWorktreeEncryptionStateRelativePath())
}

func WorktreeEncryptionKeysDir(root string) string {
	return filepath.Join(filepath.Clean(root), DefaultWorktreeEncryptionKeysRelativeDir())
}

func WorktreeEncryptionPrivateKeyRelativePath(keyID string) string {
	return filepath.Join(DefaultWorktreeEncryptionKeysRelativeDir(), encryptionKeyFileBase(keyID)+".x25519.key")
}

func WorktreeEncryptionAssertionRelativePath(keyID string) string {
	return filepath.Join(DefaultWorktreeEncryptionKeysRelativeDir(), encryptionKeyFileBase(keyID)+".assertion.json")
}

func LoadEncryptionKeyStateFrom(path string) (*EncryptionKeyState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state EncryptionKeyState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	state.normalize()
	return &state, nil
}

func SaveEncryptionKeyStateTo(path string, state *EncryptionKeyState) error {
	if state == nil {
		return errors.New("nil encryption key state")
	}
	state.normalize()
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

func (s *EncryptionKeyState) normalize() {
	if s == nil {
		return
	}
	s.ActiveKeyID = strings.TrimSpace(s.ActiveKeyID)
	keys := make([]EncryptionKeyRecord, 0, len(s.Keys))
	seen := map[string]struct{}{}
	for _, key := range s.Keys {
		key.normalize()
		if key.KeyID == "" {
			continue
		}
		if _, ok := seen[key.KeyID]; ok {
			continue
		}
		seen[key.KeyID] = struct{}{}
		keys = append(keys, key)
	}
	s.Keys = keys
}

func (r *EncryptionKeyRecord) normalize() {
	if r == nil {
		return
	}
	r.KeyID = strings.TrimSpace(r.KeyID)
	r.PublicKey = strings.TrimSpace(r.PublicKey)
	r.PrivateKeyPath = filepath.ToSlash(strings.TrimSpace(r.PrivateKeyPath))
	r.AssertionPath = filepath.ToSlash(strings.TrimSpace(r.AssertionPath))
	r.CreatedAt = strings.TrimSpace(r.CreatedAt)
	r.NotBefore = strings.TrimSpace(r.NotBefore)
	r.ExpiresAt = strings.TrimSpace(r.ExpiresAt)
	r.PublishedAt = strings.TrimSpace(r.PublishedAt)
}

func (s *EncryptionKeyState) ActiveRecord() *EncryptionKeyRecord {
	if s == nil {
		return nil
	}
	keyID := strings.TrimSpace(s.ActiveKeyID)
	if keyID == "" {
		return nil
	}
	for i := range s.Keys {
		if strings.TrimSpace(s.Keys[i].KeyID) == keyID {
			return &s.Keys[i]
		}
	}
	return nil
}

func (s *EncryptionKeyState) RecordForKeyID(keyID string) *EncryptionKeyRecord {
	if s == nil {
		return nil
	}
	keyID = strings.TrimSpace(keyID)
	for i := range s.Keys {
		if strings.TrimSpace(s.Keys[i].KeyID) == keyID {
			return &s.Keys[i]
		}
	}
	return nil
}

func (s *EncryptionKeyState) UpsertRecord(record EncryptionKeyRecord) {
	if s == nil {
		return
	}
	record.normalize()
	for i := range s.Keys {
		if strings.TrimSpace(s.Keys[i].KeyID) == record.KeyID {
			s.Keys[i] = record
			s.normalize()
			return
		}
	}
	s.Keys = append(s.Keys, record)
	s.normalize()
}

var encryptionKeyFileUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func encryptionKeyFileBase(keyID string) string {
	keyID = strings.TrimSpace(keyID)
	keyID = strings.TrimPrefix(keyID, "sha256:")
	keyID = encryptionKeyFileUnsafe.ReplaceAllString(keyID, "_")
	keyID = strings.Trim(keyID, "._-")
	if keyID == "" {
		return "unknown"
	}
	return "sha256-" + keyID
}
