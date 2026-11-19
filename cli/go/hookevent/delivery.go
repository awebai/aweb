package hookevent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/strictjson"
)

// AuthScheme prefixes the Authorization header of a hook delivery.
const AuthScheme = "AWEB-Hook DIDKey "

// SignedPayloadHeader carries the base64url canonical signed payload.
const SignedPayloadHeader = "X-AWEB-Signed-Payload"

// CertificateHeader carries a client producer's team certificate, in the
// same encoding team-auth uses.
const CertificateHeader = "X-AWID-Team-Certificate"

// ReplayWindow bounds how far a delivery's timestamp may be from the
// receiver's clock.
const ReplayWindow = 300 * time.Second

// MaxDeliveryBytes is the largest delivery body a receiver reads: an event of
// MaxEnvelopeBytes as base64url, with its signature and frame, fits well
// within it.
const MaxDeliveryBytes = 512 * 1024

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
// the second. A client producer passes its team certificate, which must name
// the event's producer key and certificate; a server producer passes nil.
func SignDelivery(key ed25519.PrivateKey, method string, target *url.URL, bindingID string, signing []byte, signature string, certificate *awid.TeamCertificate, timestamp time.Time) (*Delivery, error) {
	env, err := Open(signing)
	if err != nil {
		return nil, err
	}
	if err := VerifySignature(env.ProducerDIDKey, signing, signature); err != nil {
		return nil, err
	}
	didKey := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	if didKey != env.ProducerDIDKey {
		return nil, strictjson.Refuse("signer_mismatch", "the key is not the event's producer key")
	}
	var certificateHeader string
	if env.ProducerKind == "client" {
		if certificate == nil {
			return nil, strictjson.Refuse("certificate_missing", "a client delivery carries its team certificate")
		}
		if err := certificateNamesProducer(certificate.Team, certificate.MemberDIDKey, certificate.CertificateID, env); err != nil {
			return nil, err
		}
		certificateHeader, err = awid.EncodeTeamCertificateHeader(certificate)
		if err != nil {
			return nil, strictjson.Refuse("certificate_invalid", "%v", err)
		}
	} else if certificate != nil {
		return nil, strictjson.Refuse("invalid_value", "only a client delivery carries a team certificate")
	}
	if target == nil || target.Scheme != "https" || target.Host == "" {
		return nil, strictjson.Refuse("invalid_value", "target must be an https URL")
	}
	if !UUIDPattern.MatchString(bindingID) {
		return nil, strictjson.Refuse("invalid_value", "binding_id")
	}
	body, err := strictjson.Canonical(map[string]any{
		"hook_event": base64.RawURLEncoding.EncodeToString(signing),
		"signature":  signature,
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	path := requestPath(target)
	payload, err := strictjson.Canonical(map[string]any{
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
	headers := map[string]string{
		"Authorization":     AuthScheme + didKey + " " + authSignature,
		SignedPayloadHeader: base64.RawURLEncoding.EncodeToString(payload),
		"Content-Type":      "application/json",
	}
	if certificateHeader != "" {
		headers[CertificateHeader] = certificateHeader
	}
	return &Delivery{
		Method:        strings.ToUpper(method),
		Path:          path,
		Headers:       headers,
		Body:          body,
		SignedPayload: payload,
	}, nil
}

// ReceiveOptions are what the receiving target knows independently of the
// request: its own public origin, the binding the delivery must name, the
// current time and, for a client delivery's certificate, what the team's
// registry says: the team's current controller key, its revoked certificates
// and its registered ones, read fresh. Audience and BindingID are required.
// A target that takes client deliveries states RegisteredCertificates; left
// unstated, a client delivery is refused as verifier_misconfigured.
type ReceiveOptions struct {
	Audience               string
	BindingID              string
	TeamKeyDID             string
	RevokedCertificateIDs  []string
	RegisteredCertificates awid.RegisteredCertificates
	Now                    time.Time
}

// Received is a delivery that passed every check, with its verified event.
type Received struct {
	Payload  map[string]any
	Envelope *Envelope
}

// VerifyDelivery checks a hook delivery in the contract's order and returns
// the verified event, or the first refusal.
//
// A client delivery is authorized here by its team certificate: signed by the
// team's current controller key, for the event's team, naming the producer's
// key and certificate id. The certificate's revocation status is the shared
// team-auth verifier's to check. A server delivery is self-consistent here;
// its authority comes from the caller resolving the producer's registered
// key and active production through the team's server.
func VerifyDelivery(method, path string, headers map[string]string, body []byte, opts ReceiveOptions) (*Received, error) {
	if opts.Audience == "" || opts.BindingID == "" {
		return nil, strictjson.Refuse("verifier_misconfigured", "an audience and a binding are required")
	}
	if len(body) > MaxDeliveryBytes {
		return nil, strictjson.Refuse("request_too_large", "%d bytes, at most %d", len(body), MaxDeliveryBytes)
	}
	authorization := header(headers, "Authorization")
	if !strings.HasPrefix(authorization, AuthScheme) {
		return nil, strictjson.Refuse("wrong_scheme", "not an AWEB-Hook credential")
	}
	parts := strings.Split(strings.TrimPrefix(authorization, AuthScheme), " ")
	if len(parts) != 2 {
		return nil, strictjson.Refuse("wrong_scheme", "malformed AWEB-Hook credential")
	}
	headerDIDKey, authSignature := parts[0], parts[1]

	signedPayload, err := strictjson.DecodeBase64URL(header(headers, SignedPayloadHeader), "the signed payload")
	if err != nil {
		return nil, err
	}
	payload, err := strictjson.ParseCanonicalObject(signedPayload)
	if err != nil {
		return nil, err
	}
	if !didKeyPattern.MatchString(headerDIDKey) {
		return nil, strictjson.Refuse("bad_signature", "malformed did:key")
	}
	if err := VerifySignature(headerDIDKey, signedPayload, authSignature); err != nil {
		return nil, err
	}
	if payload["auth"] != "hook-delivery" {
		return nil, strictjson.Refuse("wrong_auth", "%v", payload["auth"])
	}
	if err := CheckKeys(payload, "", deliveryPayloadKeys, nil); err != nil {
		return nil, err
	}
	if payload["did_key"] != headerDIDKey {
		return nil, strictjson.Refuse("signer_mismatch", "payload did_key differs from the header")
	}
	if v, ok := payload["v"].(int64); !ok || v != 1 {
		return nil, strictjson.Refuse("invalid_value", "v")
	}
	teamID, ok := payload["team_id"].(string)
	if !ok || !TeamIDPattern.MatchString(teamID) {
		return nil, strictjson.Refuse("invalid_value", "team_id")
	}
	if payload["aud"] != opts.Audience {
		return nil, strictjson.Refuse("audience_mismatch", "%v", payload["aud"])
	}
	if payload["method"] != strings.ToUpper(method) || payload["path"] != path {
		return nil, strictjson.Refuse("request_mismatch", "signed for %v %v", payload["method"], payload["path"])
	}
	sum := sha256.Sum256(body)
	if payload["body_sha256"] != hex.EncodeToString(sum[:]) {
		return nil, strictjson.Refuse("body_mismatch", "body_sha256")
	}
	if err := ExactTime(payload, "timestamp", deliveryTimeLayout); err != nil {
		return nil, err
	}
	stamp := payload["timestamp"].(string)
	signedAt, _ := time.Parse(deliveryTimeLayout, stamp)
	if skew := opts.Now.Sub(signedAt); skew > ReplayWindow || skew < -ReplayWindow {
		return nil, strictjson.Refuse("timestamp_outside_window", "%s", stamp)
	}
	if payload["binding_id"] != opts.BindingID {
		return nil, strictjson.Refuse("binding_mismatch", "%v", payload["binding_id"])
	}

	bodyObject, err := strictjson.ParseCanonicalObject(body)
	if err != nil {
		return nil, strictjson.Refuse("invalid_body", "%v", err)
	}
	if err := CheckKeys(bodyObject, "body.", []string{"hook_event", "signature"}, nil); err != nil {
		return nil, strictjson.Refuse("invalid_body", "%v", err)
	}
	eventText, _ := bodyObject["hook_event"].(string)
	signing, err := base64.RawURLEncoding.Strict().DecodeString(eventText)
	if err != nil {
		return nil, strictjson.Refuse("invalid_body", "hook_event is not strict unpadded base64url")
	}
	signature, _ := bodyObject["signature"].(string)
	env, err := Verify(signing, signature, VerifyOptions{TeamID: teamID})
	if err != nil {
		return nil, err
	}
	if payload["event_id"] != env.EventID {
		return nil, strictjson.Refuse("event_mismatch", "credential names %v, body carries %s", payload["event_id"], env.EventID)
	}
	if payload["producer"] != env.Producer || payload["did_key"] != env.ProducerDIDKey || payload["kid"] != credentialKID(env) {
		return nil, strictjson.Refuse("producer_mismatch", "the credential's signer is not the event's producer")
	}
	if env.ProducerKind == "client" {
		if err := verifyClientCertificate(header(headers, CertificateHeader), env, opts); err != nil {
			return nil, err
		}
	}
	return &Received{Payload: payload, Envelope: env}, nil
}

// verifyClientCertificate checks a client delivery's certificate: that it
// names the event's producer, and then awid's one check of a team
// certificate, with the producer's key as the subject and the team's key,
// revoked and registered certificates as the target read them.
func verifyClientCertificate(encoded string, env *Envelope, opts ReceiveOptions) error {
	if encoded == "" {
		return strictjson.Refuse("certificate_missing", "a client delivery carries its team certificate")
	}
	if opts.TeamKeyDID == "" {
		return strictjson.Refuse("verifier_misconfigured", "a client delivery needs the team's current key")
	}
	certificate, err := awid.DecodeTeamCertificate(encoded)
	if err != nil {
		return strictjson.Refuse("certificate_invalid", "%v", err)
	}
	team, _ := certificate["team_id"].(string)
	member, _ := certificate["member_did_key"].(string)
	certificateID, _ := certificate["certificate_id"].(string)
	if err := certificateNamesProducer(team, member, certificateID, env); err != nil {
		return err
	}
	_, err = awid.CheckTeamCertificate(encoded, awid.TeamCertificateFacts{
		SubjectDIDKey:         env.ProducerDIDKey,
		TeamDIDKey:            opts.TeamKeyDID,
		RevokedCertificateIDs: opts.RevokedCertificateIDs,
		Registered:            opts.RegisteredCertificates,
	})
	var refused *awid.TeamCertificateError
	switch {
	case err == nil:
		return nil
	case !errors.As(err, &refused):
		return strictjson.Refuse("verifier_misconfigured", "%v", err)
	case refused.Reason == "invalid_team_key":
		return strictjson.Refuse("verifier_misconfigured", "the team key does not decode")
	case refused.Reason == "member_key_mismatch":
		return strictjson.Refuse("certificate_mismatch", "the certificate does not name this producer")
	default:
		return strictjson.Refuse("certificate_invalid", "%v", refused)
	}
}

// certificateNamesProducer requires a client's certificate to be for the
// event's team, its producer key and its certificate id.
func certificateNamesProducer(team, memberDIDKey, certificateID string, env *Envelope) error {
	producer := env.Fields["producer"].(map[string]any)
	if team != env.TeamID || memberDIDKey != env.ProducerDIDKey || certificateID != producer["certificate_id"] {
		return strictjson.Refuse("certificate_mismatch", "the certificate does not name this producer")
	}
	return nil
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
