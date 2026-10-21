package awid

// P8 contexts contain independent, current host facts, never request DTOs.
// Verification performs no persistence, authority discovery or delivery routing.
import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

type HumanChannelsPresenceIdentity struct {
	Principal, SigningKeyID string
	Active                  bool
}
type HumanChannelsPresenceGrant struct {
	Scopes       []string
	ExpiresAt    time.Time
	NeverExpires bool
}
type HumanChannelsPresenceCaller struct {
	Identity         *HumanChannelsPresenceIdentity
	ActionAuthorized bool
	Grant            *HumanChannelsPresenceGrant
}
type HumanChannelsPresenceScope struct {
	Kind      string `json:"kind"`
	SessionID string `json:"session_id,omitempty"`
}
type HumanChannelsPresenceOwnershipPin struct {
	Subject               HumanChannelsParticipant
	Audience              string
	Owner, Issuer         *HumanChannelsPresenceIdentity
	AuthorizationRevision string
}
type HumanChannelsPresenceContext struct {
	ExpectedIntentHash                    string
	Subject                               HumanChannelsParticipant
	SubjectActive                         bool
	Platform                              string
	Scope                                 HumanChannelsPresenceScope
	Mode, Audience, AuthorizationRevision string
	SubjectIdentity                       *HumanChannelsPresenceIdentity
	Caller                                HumanChannelsPresenceCaller
	ExpectedGeneration                    int64
	ConsumedRequestIDs                    []string
	Now                                   *time.Time
	MaxTTLSeconds, MaxClockSkewSeconds    int64
	OwnershipPin                          *HumanChannelsPresenceOwnershipPin
	AllowScopedNative                     bool
	BindingDigest                         string
}

func hcPresenceRecord(schema string, v any) (HumanChannelsRecord, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return HumanChannelsRecord{}, hcError("invalid", schema)
	}
	return DecodeHumanChannelsRecord(schema, b)
}
func hcPresenceIdentity(i *HumanChannelsPresenceIdentity) error {
	if i == nil {
		return hcError("authority_unavailable", "identity authority")
	}
	if _, err := hcPresenceRecord("ServiceBinding", map[string]any{"service": i.Principal, "signing_key_id": i.SigningKeyID, "audience": "presence-context"}); err != nil {
		return hcError("authority_unavailable", "identity authority")
	}
	if _, err := ExtractPublicKey(i.SigningKeyID); err != nil {
		return hcError("authority_unavailable", "identity authority")
	}
	if strings.HasPrefix(i.Principal, "did:key:") && i.Principal != i.SigningKeyID {
		return hcError("authority_unavailable", "local identity key")
	}
	if !i.Active {
		return hcError("forbidden", "inactive identity")
	}
	return nil
}
func hcPresenceBinding(v map[string]any, i *HumanChannelsPresenceIdentity) error {
	if err := hcPresenceIdentity(i); err != nil {
		return err
	}
	if v["signer"] != i.Principal && v["signer"] != i.SigningKeyID {
		return hcError("forbidden", "signer principal")
	}
	if v["signing_key_id"] != i.SigningKeyID {
		return hcError("stale", "current signing key")
	}
	return nil
}
func hcPresenceSignature(a HumanChannelsRecord, v map[string]any, i *HumanChannelsPresenceIdentity) error {
	if err := hcPresenceBinding(v, i); err != nil {
		return err
	}
	status, err := VerifySignedPayload(a.Value["signed_payload"].(string), a.Value["signature"].(string), i.SigningKeyID, i.SigningKeyID)
	if err != nil || status != Verified {
		return hcError("invalid", "signature")
	}
	return nil
}
func hcPresenceFresh(v map[string]any, c HumanChannelsPresenceContext) (time.Time, error) {
	issued, err := time.Parse("2006-01-02T15:04:05Z", v["issued_at"].(string))
	if err != nil {
		return time.Time{}, hcError("invalid", "issued_at")
	}
	expires, err := time.Parse("2006-01-02T15:04:05Z", v["expires_at"].(string))
	if err != nil {
		return time.Time{}, hcError("invalid", "expires_at")
	}
	ttl := expires.Unix() - issued.Unix()
	if ttl <= 0 || ttl > c.MaxTTLSeconds {
		return time.Time{}, hcError("invalid", "intent lifetime")
	}
	if issued.Unix()-c.Now.Unix() > c.MaxClockSkewSeconds || !expires.After(*c.Now) {
		return time.Time{}, hcError("stale", "freshness")
	}
	return expires, nil
}
func hcPresencePayload(a HumanChannelsRecord, schema string) (HumanChannelsRecord, error) {
	if a.Schema != "SignedArtifact" {
		return HumanChannelsRecord{}, hcError("invalid", "signed artifact")
	}
	if _, err := a.Canonical(); err != nil {
		return HumanChannelsRecord{}, err
	}
	return DecodeHumanChannelsRecord(schema, []byte(a.Value["signed_payload"].(string)))
}

// SignHumanChannelsPresenceRecord signs one P0 presence family. This does not
// assert that the key remains current or that its signer owns the subject.
func SignHumanChannelsPresenceRecord(r HumanChannelsRecord, key ed25519.PrivateKey) (HumanChannelsRecord, error) {
	switch r.Schema {
	case "PresenceIntent", "PresenceBindingIntent", "OwnershipProof", "BindingOwnershipProof":
	default:
		return HumanChannelsRecord{}, hcError("unsupported", "presence signing purpose")
	}
	raw, err := r.Canonical()
	if err != nil {
		return HumanChannelsRecord{}, err
	}
	r, err = DecodeHumanChannelsRecord(r.Schema, raw)
	if err != nil {
		return HumanChannelsRecord{}, err
	}
	if len(key) != ed25519.PrivateKeySize || r.Value["signing_key_id"] != ComputeDIDKey(key.Public().(ed25519.PublicKey)) {
		return HumanChannelsRecord{}, hcError("invalid", "signing key")
	}
	return hcPresenceRecord("SignedArtifact", map[string]any{"signed_payload": string(raw), "signature": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, raw))})
}
func hcVerifyPresence(a HumanChannelsRecord, c HumanChannelsPresenceContext, binding bool) (HumanChannelsRecord, error) {
	bad := HumanChannelsRecord{}
	schema := "PresenceIntent"
	if binding {
		schema = "PresenceBindingIntent"
	}
	if a.Schema != "SignedArtifact" {
		return bad, hcError("invalid", "signed artifact")
	}
	snapshot, err := a.Canonical()
	if err != nil {
		return bad, err
	}
	a, err = DecodeHumanChannelsRecord("SignedArtifact", snapshot)
	if err != nil {
		return bad, err
	}
	record, err := hcPresencePayload(a, schema)
	if err != nil {
		return bad, err
	}
	v := record.Value
	participantSchema := "NativeParticipant"
	if c.Subject.Kind == "bridged" {
		participantSchema = "BridgedParticipant"
	}
	subject, err := hcPresenceRecord(participantSchema, c.Subject)
	if err != nil {
		return bad, hcError("authority_unavailable", "subject authority")
	}
	scope, err := hcPresenceRecord("PresenceScope", c.Scope)
	if err != nil {
		return bad, hcError("authority_unavailable", "scope authority")
	}
	if c.MaxTTLSeconds <= 0 || c.MaxClockSkewSeconds < 0 || c.ExpectedGeneration < 0 || c.AuthorizationRevision == "" || c.Audience == "" || c.Now == nil || c.ExpectedIntentHash == "" {
		return bad, hcError("authority_unavailable", "verification policy")
	}
	intentDigest := sha256.Sum256([]byte(a.Value["signed_payload"].(string)))
	if c.ExpectedIntentHash != "sha256:"+hex.EncodeToString(intentDigest[:]) {
		return bad, hcError("forbidden", "authorized intent bytes")
	}
	if !c.SubjectActive || !c.Caller.ActionAuthorized {
		return bad, hcError("forbidden", "caller action authority")
	}
	if !reflect.DeepEqual(v["subject"], subject.Value) || !reflect.DeepEqual(v["scope"], scope.Value) || v["platform"] != c.Platform || v["mode"] != c.Mode || v["audience"] != c.Audience {
		return bad, hcError("forbidden", "exact presence target")
	}
	if binding {
		if c.BindingDigest == "" {
			return bad, hcError("authority_unavailable", "private binding target")
		}
		if v["binding_digest"] != c.BindingDigest {
			return bad, hcError("forbidden", "private binding target")
		}
	}
	if !binding && c.Scope.Kind == "session" && !c.AllowScopedNative {
		return bad, hcError("unsupported", "scoped native policy")
	}
	if hcNumber(v["expected_generation"]) != c.ExpectedGeneration {
		return bad, hcError("stale", "presence generation")
	}
	for _, id := range c.ConsumedRequestIDs {
		if v["request_id"] == id {
			return bad, hcError("replay_conflict", "consumed presence request")
		}
	}
	if err = hcPresenceBinding(v, c.Caller.Identity); err != nil {
		return bad, err
	}
	deadline, err := hcPresenceFresh(v, c)
	if err != nil {
		return bad, err
	}
	if g := c.Caller.Grant; g != nil {
		allowed := false
		for _, scope := range g.Scopes {
			if scope == "presence.write" {
				allowed = true
			}
		}
		if !allowed {
			return bad, hcError("forbidden", "grant scope")
		}
		if !g.NeverExpires {
			if g.ExpiresAt.IsZero() || !g.ExpiresAt.After(*c.Now) {
				return bad, hcError("forbidden", "expired grant")
			}
			if g.ExpiresAt.Before(deadline) {
				deadline = g.ExpiresAt
			}
		}
	}
	var identity *HumanChannelsPresenceIdentity
	if v["authorization"] == "subject" {
		if c.Subject.Kind != "native" {
			return bad, hcError("forbidden", "guest has no native signing identity")
		}
		identity = c.SubjectIdentity
		if err = hcPresenceIdentity(identity); err != nil {
			return bad, err
		}
		if c.Subject.DID != identity.Principal && c.Subject.DID != identity.SigningKeyID {
			return bad, hcError("authority_unavailable", "subject identity binding")
		}
	} else {
		pin := c.OwnershipPin
		if pin == nil || pin.AuthorizationRevision == "" {
			return bad, hcError("authority_unavailable", "ownership authority")
		}
		if pin.Subject != c.Subject || pin.Audience != c.Audience {
			return bad, hcError("authority_unavailable", "ownership pin target")
		}
		identity = pin.Owner
		if err = hcPresenceIdentity(identity); err != nil {
			return bad, err
		}
		if err = hcPresenceIdentity(pin.Issuer); err != nil {
			return bad, err
		}
		proofArtifact, err := hcPresenceRecord("SignedArtifact", v["ownership_proof"])
		if err != nil {
			return bad, err
		}
		proofSchema := "OwnershipProof"
		if binding {
			proofSchema = "BindingOwnershipProof"
		}
		proofRecord, err := hcPresencePayload(proofArtifact, proofSchema)
		if err != nil {
			return bad, err
		}
		proof := proofRecord.Value
		if !reflect.DeepEqual(proof["subject"], subject.Value) || proof["owner"] != identity.Principal || proof["platform"] != v["platform"] || !reflect.DeepEqual(proof["scope"], scope.Value) || proof["audience"] != c.Audience {
			return bad, hcError("forbidden", "ownership proof target")
		}
		if binding && proof["mode"] != v["mode"] {
			return bad, hcError("forbidden", "ownership proof mode")
		}
		allowed := false
		for _, op := range proof["operations"].([]any) {
			if op == v["operation"] {
				allowed = true
			}
		}
		if !allowed {
			return bad, hcError("forbidden", "ownership proof operation")
		}
		if proof["authorization_revision"] != pin.AuthorizationRevision {
			return bad, hcError("stale", "ownership revision")
		}
		if err = hcPresenceSignature(proofArtifact, proof, pin.Issuer); err != nil {
			return bad, err
		}
		expires, err := hcPresenceFresh(proof, c)
		if err != nil {
			return bad, err
		}
		if expires.Before(deadline) {
			deadline = expires
		}
	}
	if err = hcPresenceSignature(a, v, identity); err != nil {
		return bad, err
	}
	output := map[string]any{}
	for _, key := range []string{"subject", "platform", "scope", "mode", "operation", "expected_generation", "request_id"} {
		output[key] = v[key]
	}
	version := "aweb-verified-presence-v1"
	resultSchema := "VerifiedPresence"
	if binding {
		version = "aweb-verified-presence-binding-v1"
		resultSchema = "VerifiedPresenceBinding"
		output["binding_digest"] = v["binding_digest"]
	}
	hash := sha256.Sum256([]byte(a.Value["signed_payload"].(string)))
	output["version"] = version
	output["intent_hash"] = "sha256:" + hex.EncodeToString(hash[:])
	output["authorization_revision"] = c.AuthorizationRevision
	output["expires_at"] = deadline.UTC().Format("2006-01-02T15:04:05Z")
	return hcPresenceRecord(resultSchema, output)
}

// VerifyHumanChannelsNativePresence verifies the native-suppression purpose only.
func VerifyHumanChannelsNativePresence(a HumanChannelsRecord, c HumanChannelsPresenceContext) (HumanChannelsRecord, error) {
	return hcVerifyPresence(a, c, false)
}

// VerifyHumanChannelsPresenceBinding verifies shared/dedicated binding approval.
func VerifyHumanChannelsPresenceBinding(a HumanChannelsRecord, c HumanChannelsPresenceContext) (HumanChannelsRecord, error) {
	return hcVerifyPresence(a, c, true)
}
