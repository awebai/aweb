package awconfig

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ControllerMeta struct {
	Domain        string `yaml:"domain"`
	ControllerDID string `yaml:"controller_did"`
	RegistryURL   string `yaml:"registry_url"`
	CreatedAt     string `yaml:"created_at"`
}

func ControllerKeyPath(domain string) (string, error) {
	controllersDir, err := DefaultControllersDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(controllersDir, normalizeControllerDomain(domain)+".key"), nil
}

func ControllerMetaPath(domain string) (string, error) {
	controllersDir, err := DefaultControllersDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(controllersDir, normalizeControllerDomain(domain)+".yaml"), nil
}

func ControllerKeyExists(domain string) (bool, error) {
	path, err := ControllerKeyPath(domain)
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

func LoadControllerKey(domain string) (ed25519.PrivateKey, error) {
	path, err := ControllerKeyPath(domain)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in controller key")
	}
	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, errors.New("unexpected controller key PEM type")
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, errors.New("invalid controller key seed size")
	}
	return ed25519.NewKeyFromSeed(block.Bytes), nil
}

func SaveControllerKey(domain string, key ed25519.PrivateKey) error {
	if key == nil {
		return errors.New("nil controller key")
	}
	path, err := ControllerKeyPath(domain)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key.Seed(),
	})
	return atomicWriteFile(path, data)
}

func LoadControllerMeta(domain string) (*ControllerMeta, error) {
	path, err := ControllerMetaPath(domain)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta ControllerMeta
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func SaveControllerMeta(domain string, meta *ControllerMeta) error {
	if meta == nil {
		return errors.New("nil controller meta")
	}
	path, err := ControllerMetaPath(domain)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(meta)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

// NormalizeDomain lowercases, trims whitespace and trailing dots.
func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func normalizeControllerDomain(domain string) string {
	return NormalizeDomain(domain)
}
