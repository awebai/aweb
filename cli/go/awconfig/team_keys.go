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

// TeamKeyExists reports whether this machine holds the team key. A team whose
// key is set aside as unconfirmed has a key here that may be the registered
// one, so it is neither held nor absent: TeamKeyExists refuses with
// ErrTeamKeyUnconfirmed.
func TeamKeyExists(domain, name string) (bool, error) {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return false, err
	}
	if err := refuseUnconfirmedTeamKey(domain, name); err != nil {
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
	if err := teamKeyFileHolds(path, expected); err != nil {
		return err
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
	if err := refuseUnconfirmedTeamKey(domain, name); err != nil {
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

// UnconfirmedTeamKeyPath holds a team key this machine created for a team
// whose name the registry already had, when the registry could not then be
// read to say which key holds it. The key may be the registered one (another
// run on this machine registered it first), so it is kept, and never read as
// the team key, until a registry read settles it.
func UnconfirmedTeamKeyPath(domain, name string) (string, error) {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return "", err
	}
	return path + ".unconfirmed", nil
}

// ErrTeamKeyUnconfirmed reports a team whose key is set aside at
// UnconfirmedTeamKeyPath: no team key is read for it until a registry read
// restores or removes that key.
var ErrTeamKeyUnconfirmed = errors.New("team key unconfirmed")

func refuseUnconfirmedTeamKey(domain, name string) error {
	path, err := UnconfirmedTeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		domain, name = NormalizeDomain(domain), strings.ToLower(strings.TrimSpace(name))
		return fmt.Errorf("team %s/%s: %w: %s holds a key this machine created that the registry has not confirmed\nRun `aw id team create --namespace %s --name %s` (with the --registry the team was created at, if not the default) once the registry answers: it restores the key if the registry pins it and removes it if not.", domain, name, ErrTeamKeyUnconfirmed, path, domain, name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// SetAsideUnconfirmedTeamKey moves the team key file to
// UnconfirmedTeamKeyPath when it holds the expected public key, and returns
// that path. The move is a hard link then an unlink in the same directory:
// atomic, no copy, the file keeps its 0600 mode, and it never replaces a key
// already set aside (that fails with os.ErrExist and leaves both in place).
func SetAsideUnconfirmedTeamKey(domain, name string, expected ed25519.PublicKey) (string, error) {
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return "", err
	}
	if err := teamKeyFileHolds(path, expected); err != nil {
		return "", err
	}
	aside := path + ".unconfirmed"
	if err := os.Link(path, aside); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return aside, nil
}

// LoadUnconfirmedTeamKey returns the key set aside for a team and its path,
// or a nil key when there is none.
func LoadUnconfirmedTeamKey(domain, name string) (ed25519.PrivateKey, string, error) {
	path, err := UnconfirmedTeamKeyPath(domain, name)
	if err != nil {
		return nil, "", err
	}
	data, err := awid.ReadPrivateKeyFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, path, nil
	}
	if err != nil {
		return nil, path, err
	}
	key, err := decodeTeamKey(data)
	if err != nil {
		return nil, path, fmt.Errorf("%s: %w", path, err)
	}
	return key, path, nil
}

// RestoreUnconfirmedTeamKey makes the set-aside key the team key again, once
// the registry has confirmed it pins that key. It links the file back, never
// replacing a different team key file, then removes the set-aside name. A
// team key file already holding the same key (a move interrupted between its
// link and its unlink) is kept.
func RestoreUnconfirmedTeamKey(domain, name string) error {
	key, aside, err := LoadUnconfirmedTeamKey(domain, name)
	if err != nil {
		return err
	}
	if key == nil {
		return errors.New("no unconfirmed team key")
	}
	path, err := TeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	if err := os.Link(aside, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := teamKeyFileHolds(path, key.Public().(ed25519.PublicKey)); err != nil {
			return err
		}
	}
	return os.Remove(aside)
}

// RemoveUnconfirmedTeamKey deletes the set-aside key once the registry has
// confirmed it pins another key, only when the file still holds the expected
// public key.
func RemoveUnconfirmedTeamKey(domain, name string, expected ed25519.PublicKey) error {
	path, err := UnconfirmedTeamKeyPath(domain, name)
	if err != nil {
		return err
	}
	if err := teamKeyFileHolds(path, expected); err != nil {
		return err
	}
	return os.Remove(path)
}

// teamKeyFileHolds reports nil when the key file at path holds the expected
// public key, and an error matching ErrTeamKeyNotExpected when it holds
// another.
func teamKeyFileHolds(path string, expected ed25519.PublicKey) error {
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
	return nil
}
