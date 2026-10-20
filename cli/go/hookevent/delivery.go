package hookevent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

// AuthScheme prefixes the Authorization header of a hook delivery.
const AuthScheme = "AWEB-Hook DIDKey "

// SignedPayloadHeader carries the base64url canonical signed payload.
const SignedPayloadHeader = "X-AWEB-Signed-Payload"

// ReplayWindow bounds how far a delivery's timestamp may be from the
// receiver's clock.
const ReplayWindow = 300 * time.Second

const deliveryTimeLayout = "2006-01-02T15:04:05Z"

var deliveryPayloadKeys = []string{
	"v", "auth", "aud", "method", "path", "body_sha256", "team_id", "binding_id",
	"event_id", "producer", "kid", "did_key", "timestamp",
}

// Delivery is one signed hook delivery request.
type Delivery struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    []byte
	// SignedPayload is the canonical payload the Authorization signature covers.
	SignedPayload []byte
}

// SignDelivery builds the request that delivers one signed event to one
// binding. target is the binding's origin and raw path; timestamp is UTC to
// the second.
func SignDelivery(key ed25519.PrivateKey, method string, target *url.URL, bindingID string, signing []byte, signature string, timestamp time.Time) (*Delivery, error) {
	env, err := Verify(signing, signature, VerifyOptions{})
	if err != nil {
		return nil, err
	}
	didKey := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	if didKey != env.ProducerDIDKey {
		return nil, refuse("signer_mismatch", "the key is not the event's producer key")
	}
	if target == nil || target.Scheme != "https" || target.Host == "" {
		return nil, refuse("invalid_value", "target must be an https URL")
	}
	if !uuidPattern.MatchString(bindingID) {
		return nil, refuse("invalid_value", "binding_id")
	}
	body, err := Canonical(map[string]any{
		"hook_event": base64.RawURLEncoding.EncodeToString(signing),
		"signature":  signature,
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	path := requestPath(target)
	payload, err := Canonical(map[string]any{
		"v":           int64(1),
		"auth":        "hook-delivery",
		"aud":         "https://" + target.Host,
		"method":      strings.ToUpper(method),
		"path":        path,
		"body_sha256": hex.EncodeToString(sum[:]),
		"team_id":     env.TeamID,
		"binding_id":  bindingID,
		"event_id":    env.EventID,
		"producer":    env.Producer,
		"kid":         credentialKID(env),
		"did_key":     didKey,
		"timestamp":   timestamp.UTC().Format(deliveryTimeLayout),
	})
	if err != nil {
		return nil, err
	}
	authSignature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return &Delivery{
		Method: strings.ToUpper(method),
		Path:   path,
		Headers: map[string]string{
			"Authorization":     AuthScheme + didKey + " " + authSignature,
			SignedPayloadHeader: base64.RawURLEncoding.EncodeToString(payload),
			"Content-Type":      "application/json",
		},
		Body:          body,
		SignedPayload: payload,
	}, nil
}

// ReceiveOptions are what the receiving target knows independently of the
// request: its own public origin, the binding the delivery must name, and
// the current time.
type ReceiveOptions struct {
	Audience  string
	BindingID string
	Now       time.Time
}

// Received is a delivery that passed every check, with its verified event.
type Received struct {
	Payload  map[string]any
	Envelope *Envelope
}

// VerifyDelivery checks a hook delivery in the contract's order and returns
// the verified event, or the first refusal.
func VerifyDelivery(method, path string, headers map[string]string, body []byte, opts ReceiveOptions) (*Received, error) {
	authorization := header(headers, "Authorization")
	if !strings.HasPrefix(authorization, AuthScheme) {
		return nil, refuse("wrong_scheme", "not an AWEB-Hook credential")
	}
	parts := strings.Split(strings.TrimPrefix(authorization, AuthScheme), " ")
	if len(parts) != 2 {
		return nil, refuse("wrong_scheme", "malformed AWEB-Hook credential")
	}
	headerDIDKey, authSignature := parts[0], parts[1]

	encoded := header(headers, SignedPayloadHeader)
	signedPayload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, refuse("invalid_value", "signed payload is not unpadded base64url")
	}
	payload, err := parseCanonicalObject(signedPayload)
	if err != nil {
		return nil, err
	}
	if !didKeyPattern.MatchString(headerDIDKey) {
		return nil, refuse("bad_signature", "malformed did:key")
	}
	if err := verifySignature(headerDIDKey, signedPayload, authSignature); err != nil {
		return nil, err
	}
	if payload["auth"] != "hook-delivery" {
		return nil, refuse("wrong_auth", "%v", payload["auth"])
	}
	if err := checkKeys(payload, "", deliveryPayloadKeys, nil); err != nil {
		return nil, err
	}
	if payload["did_key"] != headerDIDKey {
		return nil, refuse("signer_mismatch", "payload did_key differs from the header")
	}
	if v, ok := payload["v"].(int64); !ok || v != 1 {
		return nil, refuse("invalid_value", "v")
	}
	if payload["aud"] != opts.Audience {
		return nil, refuse("audience_mismatch", "%v", payload["aud"])
	}
	if payload["method"] != strings.ToUpper(method) || payload["path"] != path {
		return nil, refuse("request_mismatch", "signed for %v %v", payload["method"], payload["path"])
	}
	sum := sha256.Sum256(body)
	if payload["body_sha256"] != hex.EncodeToString(sum[:]) {
		return nil, refuse("body_mismatch", "body_sha256")
	}
	stamp, _ := payload["timestamp"].(string)
	signedAt, err := time.Parse(deliveryTimeLayout, stamp)
	if err != nil {
		return nil, refuse("invalid_value", "timestamp")
	}
	if skew := opts.Now.Sub(signedAt); skew > ReplayWindow || skew < -ReplayWindow {
		return nil, refuse("timestamp_outside_window", "%s", stamp)
	}
	if payload["binding_id"] != opts.BindingID {
		return nil, refuse("binding_mismatch", "%v", payload["binding_id"])
	}

	bodyObject, err := parseCanonicalObject(body)
	if err != nil {
		return nil, refuse("invalid_body", "%v", err)
	}
	if err := checkKeys(bodyObject, "body.", []string{"hook_event", "signature"}, nil); err != nil {
		return nil, refuse("invalid_body", "%v", err)
	}
	eventText, _ := bodyObject["hook_event"].(string)
	signing, err := base64.RawURLEncoding.DecodeString(eventText)
	if err != nil {
		return nil, refuse("invalid_body", "hook_event is not unpadded base64url")
	}
	signature, _ := bodyObject["signature"].(string)
	teamID, _ := payload["team_id"].(string)
	env, err := Verify(signing, signature, VerifyOptions{TeamID: teamID})
	if err != nil {
		return nil, err
	}
	if payload["event_id"] != env.EventID {
		return nil, refuse("event_mismatch", "credential names %v, body carries %s", payload["event_id"], env.EventID)
	}
	if payload["producer"] != env.Producer || payload["did_key"] != env.ProducerDIDKey || payload["kid"] != credentialKID(env) {
		return nil, refuse("producer_mismatch", "the credential's signer is not the event's producer")
	}
	return &Received{Payload: payload, Envelope: env}, nil
}

// credentialKID is the key id a delivery credential names: the server
// producer's registered kid, or "member" for a client producer, whose key is
// its member key.
func credentialKID(env *Envelope) string {
	if env.ProducerKind == "client" {
		return "member"
	}
	return env.ProducerKID
}

func header(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func requestPath(target *url.URL) string {
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	if target.RawQuery != "" {
		path += "?" + target.RawQuery
	}
	return path
}
