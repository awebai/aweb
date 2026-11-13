package handoff

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

// consoleRequest is what a console-header signature covers: a request to the
// human origin, bound to a handoff result or to a console session.
type consoleRequest struct {
	Auth         string // "handoff-result" or "handoff-session"
	Audience     string // the pinned human origin
	Method       string
	Path         string // the raw request target, query included
	SubjectField string // "handoff_id" or "session_id"
	Subject      string
	Body         []byte
	Timestamp    time.Time
	Nonce        string
}

// consoleHeaders are the X-Console-* headers that sign r with the handoff's
// ephemeral key. They reuse team-auth v2's request-bound fields and
// canonical JSON, and nothing else of team-auth.
func consoleHeaders(key ed25519.PrivateKey, r consoleRequest) (http.Header, error) {
	digest := sha256.Sum256(r.Body)
	timestamp := r.Timestamp.UTC().Truncate(time.Second).Format(time.RFC3339)
	payload, err := awid.CanonicalJSONValue(map[string]any{
		"v": 2, "auth": r.Auth, "aud": r.Audience, "method": strings.ToUpper(r.Method), "path": r.Path,
		r.SubjectField: r.Subject, "body_sha256": hex.EncodeToString(digest[:]),
		"timestamp": timestamp, "nonce": r.Nonce,
	})
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Set("X-Console-Key", awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)))
	headers.Set("X-Console-Timestamp", timestamp)
	headers.Set("X-Console-Signed-Payload", base64.RawURLEncoding.EncodeToString([]byte(payload)))
	_, signature, err := awid.KeySigner(key)([]byte(payload))
	if err != nil {
		return nil, err
	}
	headers.Set("X-Console-Signature", base64.RawStdEncoding.EncodeToString(signature))
	return headers, nil
}

// newNonce is 16 random bytes as 32 lowercase hex characters.
func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
