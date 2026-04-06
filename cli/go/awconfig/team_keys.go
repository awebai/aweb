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
	return PathInUserState("team-keys")
}

func TeamKeyPath(domain, name string) (string, error) {
	dir, err := DefaultTeamKeysDir()
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
		return false, nil
	}
	return false, err
}

func SaveTeamKey(domain, name string, key ed25519.PrivateKey) error {
	if key == nil {
		return errors.New("nil team key")
	}
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key.Seed(),
	})
	return atomicWriteFile(path, data)
}

func LoadTeamKey(domain, name string) (ed25519.PrivateKey, error) {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
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
