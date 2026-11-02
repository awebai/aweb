package awconfig

import (
	"errors"
	"fmt"

	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

const humanKeychainService = "aw-human-key"

// HumanKeychain keeps human keys in the OS keychain, one item per human ID,
// holding only the encrypted backup. Any process of the same OS user may be
// able to read the item; the passphrase is what protects the key.
type HumanKeychain struct{}

func (HumanKeychain) LoadHumanKey(id string) ([]byte, error) {
	item, err := keyring.Get(humanKeychainService, id)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, awid.ErrHumanKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read the human key from the OS keychain: %w", err)
	}
	return []byte(item), nil
}

func (HumanKeychain) SaveHumanKey(id string, blob []byte) error {
	if err := awid.ValidateHumanKeyBackup(blob); err != nil {
		return fmt.Errorf("only an encrypted human key backup may be stored in the keychain: %w", err)
	}
	if err := keyring.Set(humanKeychainService, id, string(blob)); err != nil {
		return fmt.Errorf("store the human key in the OS keychain: %w", err)
	}
	return nil
}
