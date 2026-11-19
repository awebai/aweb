package handoff

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

type failedEntropy struct{}

func (failedEntropy) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestHandoffEntropyFailureIsReturnedWithoutAPanic(t *testing.T) {
	original := rand.Reader
	rand.Reader = failedEntropy{}
	t.Cleanup(func() { rand.Reader = original })
	if value, err := newNonce(); !errors.Is(err, io.ErrUnexpectedEOF) || value != "" {
		t.Fatalf("nonce=%q err=%v", value, err)
	}
	if value, err := randomToken(); !errors.Is(err, io.ErrUnexpectedEOF) || value != "" {
		t.Fatalf("token=%q err=%v", value, err)
	}
}

func TestConsoleRequestRefusesInvalidSigningMaterial(t *testing.T) {
	for _, key := range [][]byte{nil, {1, 2, 3}} {
		if headers, err := consoleHeaders(key, consoleRequest{}); err == nil || headers != nil {
			t.Fatal("invalid signer produced a console request")
		}
	}
}
