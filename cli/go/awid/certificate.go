package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// TeamCertificate is a team membership proof signed by the team controller.
// The JSON representation is used for both file storage and the
// X-AWID-Team-Certificate HTTP header.
type TeamCertificate struct {
	Version       int    `json:"version"`
	CertificateID string `json:"certificate_id"`
	Team          string `json:"team_id"`
	TeamDIDKey    string `json:"team_did_key"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	ValidityClass string `json:"validity_class,omitempty"`
	Signature     string `json:"signature"`

	scopeWireKey      string
	legacyLifetime    string
	v2WireFields      map[string]json.RawMessage
	hasLifetimeFields bool
}

// TeamCertificateFields are the inputs for signing a certificate.
type TeamCertificateFields struct {
	Team          string // team identifier (e.g. "backend:acme.com")
	MemberDIDKey  string
	MemberDIDAW   string // optional; from identity.yaml, empty for local
	MemberAddress string // optional; from identity.yaml, empty for local
	Alias         string
	IdentityScope string
	Version       int // zero preserves v1 issuance; v2 must be enabled deliberately
	ValidityClass string
	ExpiresAt     string
}

// SignTeamCertificate creates and signs a team membership certificate
// using the team's Ed25519 private key.
func SignTeamCertificate(teamKey ed25519.PrivateKey, fields TeamCertificateFields) (*TeamCertificate, error) {
	if teamKey == nil {
		return nil, fmt.Errorf("team signing key is required")
	}
	if strings.TrimSpace(fields.Team) == "" {
		return nil, fmt.Errorf("team_id is required")
	}
	if strings.TrimSpace(fields.MemberDIDKey) == "" {
		return nil, fmt.Errorf("member_did_key is required")
	}
	if strings.TrimSpace(fields.Alias) == "" {
		return nil, fmt.Errorf("alias is required")
	}

	rawScope := fields.IdentityScope
	if strings.TrimSpace(rawScope) == "" {
		return nil, fmt.Errorf("identity_scope is required")
	}
	identityScope := NormalizeIdentityScope(rawScope)
	if identityScope != IdentityModeGlobal && identityScope != IdentityModeLocal {
		return nil, fmt.Errorf("identity_scope must be %q or %q", IdentityModeGlobal, IdentityModeLocal)
	}
	certID, err := GenerateUUID4()
	if err != nil {
		return nil, err
	}
	teamDIDKey := ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	issuedAt := time.Now().UTC().Format(time.RFC3339)

	memberDIDAW := strings.TrimSpace(fields.MemberDIDAW)
	memberAddress := strings.TrimSpace(fields.MemberAddress)

	payload := canonicalCertificatePayload(certID, fields.Team, teamDIDKey, fields.MemberDIDKey, memberDIDAW, memberAddress, fields.Alias, identityScope, issuedAt, false)
	sig := ed25519.Sign(teamKey, []byte(payload))

	cert := &TeamCertificate{
		Version:       1,
		CertificateID: certID,
		Team:          fields.Team,
		TeamDIDKey:    teamDIDKey,
		MemberDIDKey:  fields.MemberDIDKey,
		MemberDIDAW:   memberDIDAW,
		MemberAddress: memberAddress,
		Alias:         fields.Alias,
		IdentityScope: identityScope,
		IssuedAt:      issuedAt,
		Signature:     base64.RawStdEncoding.EncodeToString(sig),
	}
	if fields.Version == 2 {
		cert.Version, cert.ValidityClass, cert.ExpiresAt = 2, fields.ValidityClass, fields.ExpiresAt
		if err := validateCertificateLifetime(cert, time.Now()); err != nil {
			return nil, err
		}
		payload, err := certificateV2Payload(cert)
		if err != nil {
			return nil, err
		}
		cert.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, []byte(payload)))
	} else if fields.Version != 0 && fields.Version != 1 || fields.ExpiresAt != "" || fields.ValidityClass != "" {
		return nil, fmt.Errorf("v2 is required for certificate lifetime fields")
	}
	return cert, nil
}

// VerifyTeamCertificate checks the certificate signature against the team's
// public key. Returns nil if valid, an error describing the failure otherwise.
func VerifyTeamCertificate(cert *TeamCertificate, teamPub ed25519.PublicKey) error {
	return verifyTeamCertificateAt(cert, teamPub, time.Now())
}

func verifyTeamCertificateAt(cert *TeamCertificate, teamPub ed25519.PublicKey, now time.Time) error {
	return verifyCertificate(cert, teamPub, now, true)
}

// VerifyTeamCertificateSignature authenticates an old artifact for controller
// renewal without using expired membership as authorization.
func VerifyTeamCertificateSignature(cert *TeamCertificate, teamPub ed25519.PublicKey) error {
	return verifyCertificate(cert, teamPub, time.Time{}, false)
}

func verifyCertificate(cert *TeamCertificate, teamPub ed25519.PublicKey, now time.Time, checkLifetime bool) error {
	if cert == nil {
		return fmt.Errorf("nil certificate")
	}
	if teamPub == nil {
		return fmt.Errorf("nil team public key")
	}

	if cert.Version != 1 && cert.Version != 2 {
		return fmt.Errorf("certificate_malformed: unsupported certificate version %d", cert.Version)
	}
	sig, err := base64.RawStdEncoding.DecodeString(cert.Signature)
	if err != nil {
		return fmt.Errorf("decode certificate signature: %w", err)
	}

	identityScope := NormalizeIdentityScope(cert.IdentityScope)
	if identityScope != IdentityModeGlobal && identityScope != IdentityModeLocal {
		return fmt.Errorf("certificate identity_scope is invalid")
	}
	cert.IdentityScope = identityScope

	payload := canonicalCertificatePayload(
		cert.CertificateID,
		cert.Team,
		cert.TeamDIDKey,
		cert.MemberDIDKey,
		cert.MemberDIDAW,
		cert.MemberAddress,
		cert.Alias,
		identityScope,
		cert.IssuedAt,
		false,
	)

	if cert.Version == 2 {
		payload, err = certificateV2Payload(cert)
		if err != nil {
			return err
		}
		if !ed25519.Verify(teamPub, []byte(payload), sig) {
			return fmt.Errorf("certificate signature verification failed")
		}
		if checkLifetime {
			return validateCertificateLifetime(cert, now)
		}
		return nil
	}
	if cert.hasLifetimeFields || cert.ExpiresAt != "" || cert.ValidityClass != "" {
		return fmt.Errorf("certificate_malformed: lifetime fields require version 2")
	}
	if !ed25519.Verify(teamPub, []byte(payload), sig) {
		legacyPayload := canonicalCertificatePayload(
			cert.CertificateID,
			cert.Team,
			cert.TeamDIDKey,
			cert.MemberDIDKey,
			cert.MemberDIDAW,
			cert.MemberAddress,
			cert.Alias,
			cert.legacyLifetime,
			cert.IssuedAt,
			true,
		)
		if !ed25519.Verify(teamPub, []byte(legacyPayload), sig) {
			return fmt.Errorf("certificate signature verification failed")
		}
	}
	return nil
}

// SaveTeamCertificate writes a certificate to disk as JSON with 0600 permissions.
func SaveTeamCertificate(path string, cert *TeamCertificate) error {
	data, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal certificate: %w", err)
	}
	data = append(data, '\n')
	return atomicWriteFile(path, data)
}

// LoadTeamCertificate reads a certificate from disk.
func LoadTeamCertificate(path string) (*TeamCertificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cert TeamCertificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return &cert, nil
}

// EncodeTeamCertificateHeader encodes a certificate for the
// X-AWID-Team-Certificate HTTP header (base64 JSON).
func EncodeTeamCertificateHeader(cert *TeamCertificate) (string, error) {
	data, err := json.Marshal(cert)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodeTeamCertificateHeader decodes a certificate from the
// X-AWID-Team-Certificate HTTP header. This transport envelope deliberately
// uses padded StdEncoding to round-trip headers emitted by TypeScript's
// encodeTeamCertificateHeader; RawStdEncoding would reject those headers.
func DecodeTeamCertificateHeader(encoded string) (*TeamCertificate, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode certificate header: %w", err)
	}
	var cert TeamCertificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("parse certificate header: %w", err)
	}
	return &cert, nil
}

func (c TeamCertificate) MarshalJSON() ([]byte, error) {
	if c.Version == 2 {
		payload := certificateV2Fields(&c)
		payload["signature"] = c.Signature
		return json.Marshal(payload)
	}
	type canonicalWire struct {
		Version       int    `json:"version"`
		CertificateID string `json:"certificate_id"`
		Team          string `json:"team_id"`
		TeamDIDKey    string `json:"team_did_key"`
		MemberDIDKey  string `json:"member_did_key"`
		MemberDIDAW   string `json:"member_did_aw,omitempty"`
		MemberAddress string `json:"member_address,omitempty"`
		Alias         string `json:"alias"`
		IdentityScope string `json:"identity_scope"`
		IssuedAt      string `json:"issued_at"`
		ExpiresAt     string `json:"expires_at,omitempty"`
		ValidityClass string `json:"validity_class,omitempty"`
		Signature     string `json:"signature"`
	}
	identityScope := NormalizeIdentityScope(c.IdentityScope)
	if c.scopeWireKey == "lifetime" {
		type legacyWire struct {
			Version       int    `json:"version"`
			CertificateID string `json:"certificate_id"`
			Team          string `json:"team_id"`
			TeamDIDKey    string `json:"team_did_key"`
			MemberDIDKey  string `json:"member_did_key"`
			MemberDIDAW   string `json:"member_did_aw,omitempty"`
			MemberAddress string `json:"member_address,omitempty"`
			Alias         string `json:"alias"`
			Lifetime      string `json:"lifetime"`
			IssuedAt      string `json:"issued_at"`
			ExpiresAt     string `json:"expires_at,omitempty"`
			ValidityClass string `json:"validity_class,omitempty"`
			Signature     string `json:"signature"`
		}
		return json.Marshal(legacyWire{
			Version:       c.Version,
			CertificateID: c.CertificateID,
			Team:          c.Team,
			TeamDIDKey:    c.TeamDIDKey,
			MemberDIDKey:  c.MemberDIDKey,
			MemberDIDAW:   c.MemberDIDAW,
			MemberAddress: c.MemberAddress,
			Alias:         c.Alias,
			Lifetime:      c.legacyLifetime,
			IssuedAt:      c.IssuedAt,
			Signature:     c.Signature,
		})
	}
	return json.Marshal(canonicalWire{
		Version:       c.Version,
		CertificateID: c.CertificateID,
		Team:          c.Team,
		TeamDIDKey:    c.TeamDIDKey,
		MemberDIDKey:  c.MemberDIDKey,
		MemberDIDAW:   c.MemberDIDAW,
		MemberAddress: c.MemberAddress,
		Alias:         c.Alias,
		IdentityScope: identityScope,
		IssuedAt:      c.IssuedAt,
		Signature:     c.Signature,
	})
}

func (c *TeamCertificate) UnmarshalJSON(data []byte) error {
	type wire struct {
		Version       int    `json:"version"`
		CertificateID string `json:"certificate_id"`
		Team          string `json:"team_id"`
		TeamDIDKey    string `json:"team_did_key"`
		MemberDIDKey  string `json:"member_did_key"`
		MemberDIDAW   string `json:"member_did_aw,omitempty"`
		MemberAddress string `json:"member_address,omitempty"`
		Alias         string `json:"alias"`
		IdentityScope string `json:"identity_scope"`
		Lifetime      string `json:"lifetime"`
		IssuedAt      string `json:"issued_at"`
		ExpiresAt     string `json:"expires_at,omitempty"`
		ValidityClass string `json:"validity_class,omitempty"`
		Signature     string `json:"signature"`
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if value, ok := raw["expires_at"]; ok && (string(value) == "null" || string(value) == `""`) {
		return fmt.Errorf("certificate_malformed: expires_at must be a timestamp when present")
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	_, hasExpiry := raw["expires_at"]
	_, hasClass := raw["validity_class"]
	identityScope := NormalizeIdentityScope(w.IdentityScope)
	scopeWireKey := "identity_scope"
	if strings.TrimSpace(w.IdentityScope) == "" && strings.TrimSpace(w.Lifetime) != "" {
		identityScope = IdentityScopeFromLegacyLifetime(w.Lifetime)
		scopeWireKey = "lifetime"
	}
	*c = TeamCertificate{
		hasLifetimeFields: hasExpiry || hasClass,
		Version:           w.Version,
		CertificateID:     w.CertificateID,
		Team:              w.Team,
		TeamDIDKey:        w.TeamDIDKey,
		MemberDIDKey:      w.MemberDIDKey,
		MemberDIDAW:       w.MemberDIDAW,
		MemberAddress:     w.MemberAddress,
		Alias:             w.Alias,
		IdentityScope:     identityScope,
		IssuedAt:          w.IssuedAt,
		ExpiresAt:         w.ExpiresAt,
		ValidityClass:     w.ValidityClass,
		Signature:         w.Signature,
		scopeWireKey:      scopeWireKey,
		legacyLifetime:    strings.TrimSpace(w.Lifetime),
	}
	if w.Version == 2 {
		c.v2WireFields = raw
	}
	return nil
}

// canonicalCertificatePayload builds the canonical JSON for certificate signing.
// The payload must match exactly what the verifier reconstructs: the certificate
// JSON (minus signature) serialized with sorted keys, no whitespace, and native
// types (version as int, omitted empty optional fields).
func canonicalCertificatePayload(certID, team, teamDIDKey, memberDIDKey, memberDIDAW, memberAddress, alias, scopeOrLifetime, issuedAt string, legacyLifetime bool) string {
	type entry struct {
		key string
		val string // serialized JSON value (already quoted for strings)
	}

	scopeKey := "identity_scope"
	if legacyLifetime {
		scopeKey = "lifetime"
	}
	entries := []entry{
		{"alias", jsonString(alias)},
		{"certificate_id", jsonString(certID)},
		{"issued_at", jsonString(issuedAt)},
		{scopeKey, jsonString(scopeOrLifetime)},
	}
	if memberAddress != "" {
		entries = append(entries, entry{"member_address", jsonString(memberAddress)})
	}
	if memberDIDAW != "" {
		entries = append(entries, entry{"member_did_aw", jsonString(memberDIDAW)})
	}
	entries = append(entries,
		entry{"member_did_key", jsonString(memberDIDKey)},
		entry{"team_did_key", jsonString(teamDIDKey)},
		entry{"team_id", jsonString(team)},
		entry{"version", "1"},
	)

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].key < entries[j].key
	})

	var b strings.Builder
	b.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(e.key)
		b.WriteString(`":`)
		b.WriteString(e.val)
	}
	b.WriteByte('}')
	return b.String()
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	writeEscapedString(&b, s)
	b.WriteByte('"')
	return b.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// v2 uses an independent signed validity class, never the legacy scope field.
func certificateV2Fields(c *TeamCertificate) map[string]any {
	fields := map[string]any{
		"version": c.Version, "certificate_id": c.CertificateID, "team_id": c.Team,
		"team_did_key": c.TeamDIDKey, "member_did_key": c.MemberDIDKey,
		"alias": c.Alias, "identity_scope": c.IdentityScope, "issued_at": c.IssuedAt,
		"validity_class": c.ValidityClass,
	}
	if c.MemberDIDAW != "" {
		fields["member_did_aw"] = c.MemberDIDAW
	}
	if c.MemberAddress != "" {
		fields["member_address"] = c.MemberAddress
	}
	if c.ExpiresAt != "" {
		fields["expires_at"] = c.ExpiresAt
	}
	// Preserve signed extension fields and explicit empty optional fields when
	// transporting a received artifact. Changes to known fields still change
	// the reconstructed payload, so callers cannot mutate a verified binding.
	for name, raw := range c.v2WireFields {
		if name == "signature" {
			continue
		}
		if _, known := fields[name]; !known {
			var decoded any
			if json.Unmarshal(raw, &decoded) == nil {
				fields[name] = decoded
			}
		}
	}
	for name, value := range map[string]string{
		"member_did_aw": c.MemberDIDAW, "member_address": c.MemberAddress, "expires_at": c.ExpiresAt,
	} {
		if raw, present := c.v2WireFields[name]; present {
			var original string
			_ = json.Unmarshal(raw, &original)
			if original != value {
				fields[name] = value
			}
		}
	}
	return fields
}

func certificateV2Payload(c *TeamCertificate) (string, error) {
	return CanonicalJSONValue(certificateV2Fields(c))
}

func validateCertificateLifetime(c *TeamCertificate, now time.Time) error {
	if c.ValidityClass != "member" && c.ValidityClass != "ephemeral" {
		return fmt.Errorf("certificate_malformed: invalid validity_class")
	}
	issued, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	if err != nil {
		return fmt.Errorf("certificate_malformed: invalid issued_at")
	}
	if c.ExpiresAt == "" {
		return nil
	}
	expires, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return fmt.Errorf("certificate_malformed: invalid expires_at")
	}
	if !expires.After(now) {
		return fmt.Errorf("certificate_expired: team certificate expired")
	}
	return nil
}
