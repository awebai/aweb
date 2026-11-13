package awconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

// An agent host keeps one owner-signed log-key record per team under
// ~/.config/aw/log-keys/. It is public: the private half never leaves the
// owner's keychain.

const logKeychainService = "aw-log-key"

// ErrLogKeyNotFound means the owner's keychain holds no log key for a key id.
var ErrLogKeyNotFound = errors.New("no owner log key in the keychain")

func LogKeyRecordPath(teamID string) (string, error) {
	return PathInUserState("log-keys", EncodeTeamIDForCertificatePath(teamID)+".json")
}

// LoadLogKeyRecord returns the installed record for teamID, unverified. A
// missing record is os.ErrNotExist.
func LoadLogKeyRecord(teamID string) (*awid.LogKeyRecord, error) {
	path, err := LogKeyRecordPath(teamID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec awid.LogKeyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parse log key record %s: %w", path, err)
	}
	return &rec, nil
}

// SaveLogKeyRecord installs rec as its team's log key, replacing any other.
func SaveLogKeyRecord(rec *awid.LogKeyRecord) error {
	if rec == nil {
		return errors.New("missing log key record")
	}
	path, err := LogKeyRecordPath(rec.TeamID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'))
}

// LogKeychain keeps owner log keys in the OS keychain, one item per key id,
// holding only the encrypted backup. Like the human key, the passphrase is
// what protects it from other processes of the same OS user.
type LogKeychain struct{}

func (LogKeychain) LoadLogKey(keyID string) ([]byte, error) {
	item, err := keyring.Get(logKeychainService, keyID)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrLogKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read the log key from the OS keychain: %w", err)
	}
	return []byte(item), nil
}

func (LogKeychain) SaveLogKey(keyID string, blob []byte) error {
	if err := awid.ValidateHumanKeyBackup(blob); err != nil {
		return fmt.Errorf("only an encrypted log key backup may be stored in the keychain: %w", err)
	}
	if err := keyring.Set(logKeychainService, keyID, string(blob)); err != nil {
		return fmt.Errorf("store the log key in the OS keychain: %w", err)
	}
	return nil
}

// LockLogKeyPolicy serializes installing a team's log-key record with every
// local log write that resolves it, so no write can act on a decision made
// before an install completed.
func LockLogKeyPolicy(teamID string) (*fileLock, error) {
	path, err := LogKeyRecordPath(teamID)
	if err != nil {
		return nil, err
	}
	return LockExclusive(path + ".lock")
}
