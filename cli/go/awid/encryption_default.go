package awid

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoPublishedEncryptionKey matches the error for a recipient that has no
// published E2E encryption key at all. A key that exists but fails its checks
// is a different error, and never matches.
var ErrNoPublishedEncryptionKey = errors.New("recipient has no published E2E encryption key")

type noEncryptionKeyError struct {
	message string
}

func (e *noEncryptionKeyError) Error() string { return e.message }

func (e *noEncryptionKeyError) Is(target error) bool { return target == ErrNoPublishedEncryptionKey }

func noEncryptionKey(format string, args ...any) error {
	return &noEncryptionKeyError{message: fmt.Sprintf(format, args...)}
}

// NoPublishedKeyReason says why a send that encrypts by default went out as
// server-readable plaintext.
const NoPublishedKeyReason = "the recipient has no published encryption key"

// SendWithEncryptionDefault sends encrypted when encrypt is set. Otherwise, if
// the identity encrypts by default, it prepares the client and tries an
// encrypted send: a recipient with no published key is found before anything
// is sent, and only then does the send go out as plaintext, with the reason.
// Any other failure, including a sender that cannot encrypt or a recipient key
// that fails its checks, fails the send.
func SendWithEncryptionDefault[T any](ctx context.Context, encrypt, byDefault bool, prepare func(context.Context) error, send func(encrypt bool) (T, error)) (T, string, error) {
	if encrypt || !byDefault || prepare == nil {
		out, err := send(encrypt)
		return out, "", err
	}
	if err := prepare(ctx); err != nil {
		var zero T
		return zero, "", fmt.Errorf("messaging.encrypt_by_default is on, so this send must be encrypted: %w", err)
	}
	out, err := send(true)
	if errors.Is(err, ErrNoPublishedEncryptionKey) {
		out, err = send(false)
		return out, NoPublishedKeyReason, err
	}
	return out, "", err
}
