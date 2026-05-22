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
	// Lifetime is a deprecated local compatibility alias. It is accepted when
	// loading old certificates but is not emitted by new certificate JSON.
	Lifetime  string `json:"-"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`

	scopeWireKey string
}

// TeamCertificateFields are the inputs for signing a certificate.
type TeamCertificateFields struct {
	Team          string // team identifier (e.g. "backend:acme.com")
	MemberDIDKey  string
	MemberDIDAW   string // optional; from identity.yaml, empty for local
	MemberAddress string // optional; from identity.yaml, empty for local
	Alias         string
	IdentityScope string
	// Lifetime is a deprecated compatibility input; use IdentityScope.
	Lifetime string
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

	rawScope := firstNonEmpty(fields.IdentityScope, fields.Lifetime)
	if strings.TrimSpace(rawScope) == "" {
		return nil, fmt.Errorf("identity_scope is required")
	}
	identityScope := NormalizeIdentityScope(rawScope)
	if identityScope != IdentityModeGlobal && identityScope != IdentityModeLocal {
		return nil, fmt.Errorf("identity_scope must be %q or %q", IdentityModeGlobal, IdentityModeLocal)
	}
	legacyLifetime := LegacyLifetimeForIdentityScope(identityScope)

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

	return &TeamCertificate{
		Version:       1,
		CertificateID: certID,
		Team:          fields.Team,
		TeamDIDKey:    teamDIDKey,
		MemberDIDKey:  fields.MemberDIDKey,
		MemberDIDAW:   memberDIDAW,
		MemberAddress: memberAddress,
		Alias:         fields.Alias,
		IdentityScope: identityScope,
		Lifetime:      legacyLifetime,
		IssuedAt:      issuedAt,
		Signature:     base64.RawStdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyTeamCertificate checks the certificate signature against the team's
// public key. Returns nil if valid, an error describing the failure otherwise.
func VerifyTeamCertificate(cert *TeamCertificate, teamPub ed25519.PublicKey) error {
	if cert == nil {
		return fmt.Errorf("nil certificate")
	}
	if teamPub == nil {
		return fmt.Errorf("nil team public key")
	}

	sig, err := base64.RawStdEncoding.DecodeString(cert.Signature)
	if err != nil {
		return fmt.Errorf("decode certificate signature: %w", err)
	}

	identityScope := NormalizeIdentityScope(firstNonEmpty(cert.IdentityScope, cert.Lifetime))
	if identityScope != IdentityModeGlobal && identityScope != IdentityModeLocal {
		return fmt.Errorf("certificate identity_scope is invalid")
	}
	cert.IdentityScope = identityScope
	cert.Lifetime = LegacyLifetimeForIdentityScope(identityScope)

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

	if !ed25519.Verify(teamPub, []byte(payload), sig) {
		legacyPayload := canonicalCertificatePayload(
			cert.CertificateID,
			cert.Team,
			cert.TeamDIDKey,
			cert.MemberDIDKey,
			cert.MemberDIDAW,
			cert.MemberAddress,
			cert.Alias,
			cert.Lifetime,
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
// X-AWID-Team-Certificate HTTP header.
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
		Signature     string `json:"signature"`
	}
	identityScope := NormalizeIdentityScope(firstNonEmpty(c.IdentityScope, c.Lifetime))
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
			Lifetime:      LegacyLifetimeForIdentityScope(identityScope),
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
		Signature     string `json:"signature"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	identityScope := NormalizeIdentityScope(firstNonEmpty(w.IdentityScope, w.Lifetime))
	scopeWireKey := "identity_scope"
	if strings.TrimSpace(w.IdentityScope) == "" && strings.TrimSpace(w.Lifetime) != "" {
		scopeWireKey = "lifetime"
	}
	*c = TeamCertificate{
		Version:       w.Version,
		CertificateID: w.CertificateID,
		Team:          w.Team,
		TeamDIDKey:    w.TeamDIDKey,
		MemberDIDKey:  w.MemberDIDKey,
		MemberDIDAW:   w.MemberDIDAW,
		MemberAddress: w.MemberAddress,
		Alias:         w.Alias,
		IdentityScope: identityScope,
		Lifetime:      LegacyLifetimeForIdentityScope(identityScope),
		IssuedAt:      w.IssuedAt,
		Signature:     w.Signature,
		scopeWireKey:  scopeWireKey,
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
