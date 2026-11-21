package awconfig

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awid"
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

// CreateTeamKey saves the key of a team this machine is creating. It never
// replaces a key file: when one is already there, for example because another
// run creating the same team saved its key first, it fails with an error
// matching os.ErrExist and leaves that key untouched.
func CreateTeamKey(domain, name string, key ed25519.PrivateKey) error {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	if key == nil {
		return errors.New("nil team key")
	}
	return awid.StoreSigningKeyFile(awid.SigningKeyFile{Path: path, Key: key, PathPolicy: awid.OperatorManagedAuthorityPath, Exclusive: true})
}

func writeTeamKeyFile(path string, key ed25519.PrivateKey) error {
	if key == nil {
		return errors.New("nil team key")
	}
	return awid.StoreSigningKeyFile(awid.SigningKeyFile{Path: path, Key: key, PathPolicy: awid.OperatorManagedAuthorityPath})
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
	data, err := awid.ReadPrivateKeyFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeTeamKey(data)
}

// ErrTeamKeyNotExpected reports a team key file holding a key other than the
// one the caller meant to remove.
var ErrTeamKeyNotExpected = errors.New("team key file holds a different key")

// RemoveTeamKey deletes the team key file only when it holds the expected
// public key: the key a run created and never registered. Any other key is
// left in place and the error matches ErrTeamKeyNotExpected.
func RemoveTeamKey(domain, name string, expected ed25519.PublicKey) error {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	data, err := awid.ReadPrivateKeyFile(path)
	if err != nil {
		return err
	}
	key, err := decodeTeamKey(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	held, ok := key.Public().(ed25519.PublicKey)
	if !ok || !held.Equal(expected) {
		return fmt.Errorf("%s: %w", path, ErrTeamKeyNotExpected)
	}
	return os.Remove(path)
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
	data, err := awid.ReadPrivateKeyFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		legacyPath, legacyErr := legacyTeamKeyPath(domain, name)
		if legacyErr != nil {
			return nil, legacyErr
		}
		data, err = awid.ReadPrivateKeyFile(legacyPath)
		if err != nil {
			return nil, err
		}
	}
	return decodeTeamKey(data)
}

func decodeTeamKey(data []byte) (ed25519.PrivateKey, error) { return awid.ParseSigningKey(data) }
