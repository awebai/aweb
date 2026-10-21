package awconfig

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func DefaultTeamKeysDir() (string, error) {
	return PathInAWIDState("team-keys")
}

func legacyTeamKeysDir() (string, error) {
	return PathInUserState("team-keys")
}

func TeamKeyPath(domain, name string) (string, error) {
	dir, err := DefaultTeamKeysDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, NormalizeDomain(domain), strings.ToLower(strings.TrimSpace(name))+".key"), nil
}

func legacyTeamKeyPath(domain, name string) (string, error) {
	dir, err := legacyTeamKeysDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, NormalizeDomain(domain), strings.ToLower(strings.TrimSpace(name))+".key"), nil
}

func TeamKeyExists(domain, name string) (bool, error) {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		legacyPath, legacyErr := legacyTeamKeyPath(domain, name)
		if legacyErr != nil {
			return false, legacyErr
		}
		_, legacyErr = os.Stat(legacyPath)
		if legacyErr == nil {
			return true, nil
		}
		if errors.Is(legacyErr, os.ErrNotExist) {
			return false, nil
		}
		return false, legacyErr
	}
	return false, err
}

func SaveTeamKey(domain, name string, key ed25519.PrivateKey) error {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	return writeTeamKeyFile(path, key)
}

func writeTeamKeyFile(path string, key ed25519.PrivateKey) error {
	if key == nil {
		return errors.New("nil team key")
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key.Seed(),
	})
	return atomicWriteFile(path, data)
}

// PendingTeamKeyPath holds a new team key between its creation and the
// registry accepting it, so an interrupted rotation never loses the key AWID
// may already hold.
func PendingTeamKeyPath(domain, name string) (string, error) {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return "", err
	}
	return path + ".pending", nil
}

func SavePendingTeamKey(domain, name string, key ed25519.PrivateKey) error {
	path, err := PendingTeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	return writeTeamKeyFile(path, key)
}

// LoadPendingTeamKey returns the pending team key, or nil when there is none.
func LoadPendingTeamKey(domain, name string) (ed25519.PrivateKey, error) {
	path, err := PendingTeamKeyPath(domain, name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeTeamKey(data)
}

// PromotePendingTeamKey makes the pending key the team key and removes it.
func PromotePendingTeamKey(domain, name string) error {
	key, err := LoadPendingTeamKey(domain, name)
	if err != nil {
		return err
	}
	if key == nil {
		return errors.New("no pending team key")
	}
	if err := SaveTeamKey(domain, name, key); err != nil {
		return err
	}
	path, err := PendingTeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func LoadTeamKey(domain, name string) (ed25519.PrivateKey, error) {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		legacyPath, legacyErr := legacyTeamKeyPath(domain, name)
		if legacyErr != nil {
			return nil, legacyErr
		}
		data, err = os.ReadFile(legacyPath)
		if err != nil {
			return nil, err
		}
	}
	return decodeTeamKey(data)
}

func decodeTeamKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in team key")
	}
	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, errors.New("unexpected team key PEM type")
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, errors.New("invalid team key seed size")
	}
	return ed25519.NewKeyFromSeed(block.Bytes), nil
}
