package awconfig

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

type ControllerMeta struct {
	Domain        string `yaml:"domain"`
	ControllerDID string `yaml:"controller_did"`
	RegistryURL   string `yaml:"registry_url"`
	CreatedAt     string `yaml:"created_at"`

	RegistryOperatorOrigin string `yaml:"registry_operator_origin"`
	LegacyRegistryOrigin   bool   `yaml:"-"`
}

func (m *ControllerMeta) UnmarshalYAML(value *yaml.Node) error {
	var wire struct {
		Domain                 string  `yaml:"domain"`
		ControllerDID          string  `yaml:"controller_did"`
		RegistryURL            string  `yaml:"registry_url"`
		CreatedAt              string  `yaml:"created_at"`
		RegistryOperatorOrigin *string `yaml:"registry_operator_origin"`
	}
	if err := value.Decode(&wire); err != nil {
		return err
	}
	*m = ControllerMeta{Domain: wire.Domain, ControllerDID: wire.ControllerDID,
		RegistryURL: wire.RegistryURL, CreatedAt: wire.CreatedAt,
		LegacyRegistryOrigin: wire.RegistryOperatorOrigin == nil}
	if wire.RegistryOperatorOrigin != nil {
		m.RegistryOperatorOrigin = *wire.RegistryOperatorOrigin
	}
	return nil
}

func ControllerKeyPath(domain string) (string, error) {
	controllersDir, err := DefaultControllersDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(controllersDir, normalizeControllerDomain(domain)+".key"), nil
}

func legacyControllerKeyPath(domain string) (string, error) {
	controllersDir, err := LegacyControllersDir()
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

func legacyControllerMetaPath(domain string) (string, error) {
	controllersDir, err := LegacyControllersDir()
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
		legacyPath, legacyErr := legacyControllerKeyPath(domain)
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

func LoadControllerKey(domain string) (ed25519.PrivateKey, error) {
	path, err := ControllerKeyPath(domain)
	if err != nil {
		return nil, err
	}
	data, err := awid.ReadPrivateKeyFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		legacyPath, legacyErr := legacyControllerKeyPath(domain)
		if legacyErr != nil {
			return nil, legacyErr
		}
		data, err = awid.ReadPrivateKeyFile(legacyPath)
		if err != nil {
			return nil, err
		}
	}
	return awid.ParseSigningKey(data)
}

func SaveControllerKey(domain string, key ed25519.PrivateKey) error {
	if key == nil {
		return errors.New("nil controller key")
	}
	path, err := ControllerKeyPath(domain)
	if err != nil {
		return err
	}
	return awid.StoreSigningKeyFile(awid.SigningKeyFile{Path: path, Key: key, PathPolicy: awid.OperatorManagedAuthorityPath})
}

func LoadControllerMeta(domain string) (*ControllerMeta, error) {
	path, err := ControllerMetaPath(domain)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		legacyPath, legacyErr := legacyControllerMetaPath(domain)
		if legacyErr != nil {
			return nil, legacyErr
		}
		data, err = os.ReadFile(legacyPath)
		if err != nil {
			return nil, err
		}
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
