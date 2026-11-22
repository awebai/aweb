package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/canonicaljson"
	"github.com/awebai/aw/signaturewire"
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
	Signature     string `json:"signature"`

	scopeWireKey       string
	legacyLifetime     string
	emptyMemberDIDAW   bool
	emptyMemberAddress bool
}

// TeamCertificateFields are the inputs for signing a certificate.
type TeamCertificateFields struct {
	Team          string // team identifier (e.g. "backend:acme.com")
	MemberDIDKey  string
	MemberDIDAW   string // optional; from identity.yaml, empty for local
	MemberAddress string // optional; from identity.yaml, empty for local
	Alias         string
	IdentityScope string
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

	payload := canonicalCertificatePayload(certificatePayloadFields{CertificateID: certID, TeamID: fields.Team, TeamDIDKey: teamDIDKey, MemberDIDKey: fields.MemberDIDKey, MemberDIDAW: memberDIDAW, MemberAddress: memberAddress, Alias: fields.Alias, Scope: identityScope, IssuedAt: issuedAt, ScopeField: certificateIdentityScopeField})
	sig := signaturewire.SignBytes(teamKey, []byte(payload))

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
		IssuedAt:      issuedAt,
		Signature:     base64.RawStdEncoding.EncodeToString(sig),
	}, nil
}

// SaveTeamCertificate writes a certificate to disk as JSON with 0600 permissions.
func SaveTeamCertificate(path string, cert *TeamCertificate) error {
	data, err := EncodeTeamCertificateFile(cert)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data)
}

// EncodeTeamCertificateFile is cert as a certificate file holds it.
func EncodeTeamCertificateFile(cert *TeamCertificate) ([]byte, error) {
	data, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal certificate: %w", err)
	}
	return append(data, '\n'), nil
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
	type canonicalWire struct {
		Version       int     `json:"version"`
		CertificateID string  `json:"certificate_id"`
		Team          string  `json:"team_id"`
		TeamDIDKey    string  `json:"team_did_key"`
		MemberDIDKey  string  `json:"member_did_key"`
		MemberDIDAW   *string `json:"member_did_aw,omitempty"`
		MemberAddress *string `json:"member_address,omitempty"`
		Alias         string  `json:"alias"`
		IdentityScope string  `json:"identity_scope"`
		IssuedAt      string  `json:"issued_at"`
		Signature     string  `json:"signature"`
	}
	identityScope := NormalizeIdentityScope(c.IdentityScope)
	memberDIDAW := optionalCertificateString(c.MemberDIDAW, c.emptyMemberDIDAW)
	memberAddress := optionalCertificateString(c.MemberAddress, c.emptyMemberAddress)
	if c.scopeWireKey == "lifetime" {
		type legacyWire struct {
			Version       int     `json:"version"`
			CertificateID string  `json:"certificate_id"`
			Team          string  `json:"team_id"`
			TeamDIDKey    string  `json:"team_did_key"`
			MemberDIDKey  string  `json:"member_did_key"`
			MemberDIDAW   *string `json:"member_did_aw,omitempty"`
			MemberAddress *string `json:"member_address,omitempty"`
			Alias         string  `json:"alias"`
			Lifetime      string  `json:"lifetime"`
			IssuedAt      string  `json:"issued_at"`
			Signature     string  `json:"signature"`
		}
		return json.Marshal(legacyWire{
			Version:       c.Version,
			CertificateID: c.CertificateID,
			Team:          c.Team,
			TeamDIDKey:    c.TeamDIDKey,
			MemberDIDKey:  c.MemberDIDKey,
			MemberDIDAW:   memberDIDAW,
			MemberAddress: memberAddress,
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
		MemberDIDAW:   memberDIDAW,
		MemberAddress: memberAddress,
		Alias:         c.Alias,
		IdentityScope: identityScope,
		IssuedAt:      c.IssuedAt,
		Signature:     c.Signature,
	})
}

// A loaded certificate may sign an explicit empty string. Preserve it when
// forwarding that artifact. New certificates omit unused optional claims.
func optionalCertificateString(value string, signedEmpty bool) *string {
	if value == "" && !signedEmpty {
		return nil
	}
	return &value
}

func (c *TeamCertificate) UnmarshalJSON(data []byte) error {
	type wire struct {
		Version       int     `json:"version"`
		CertificateID string  `json:"certificate_id"`
		Team          string  `json:"team_id"`
		TeamDIDKey    string  `json:"team_did_key"`
		MemberDIDKey  string  `json:"member_did_key"`
		MemberDIDAW   *string `json:"member_did_aw,omitempty"`
		MemberAddress *string `json:"member_address,omitempty"`
		Alias         string  `json:"alias"`
		IdentityScope string  `json:"identity_scope"`
		Lifetime      string  `json:"lifetime"`
		IssuedAt      string  `json:"issued_at"`
		Signature     string  `json:"signature"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	identityScope := NormalizeIdentityScope(w.IdentityScope)
	scopeWireKey := "identity_scope"
	if strings.TrimSpace(w.IdentityScope) == "" && strings.TrimSpace(w.Lifetime) != "" {
		identityScope = IdentityScopeFromLegacyLifetime(w.Lifetime)
		scopeWireKey = "lifetime"
	}
	*c = TeamCertificate{
		Version:        w.Version,
		CertificateID:  w.CertificateID,
		Team:           w.Team,
		TeamDIDKey:     w.TeamDIDKey,
		MemberDIDKey:   w.MemberDIDKey,
		Alias:          w.Alias,
		IdentityScope:  identityScope,
		IssuedAt:       w.IssuedAt,
		Signature:      w.Signature,
		scopeWireKey:   scopeWireKey,
		legacyLifetime: strings.TrimSpace(w.Lifetime),
	}
	if w.MemberDIDAW != nil {
		c.MemberDIDAW = *w.MemberDIDAW
		c.emptyMemberDIDAW = c.MemberDIDAW == ""
	}
	if w.MemberAddress != nil {
		c.MemberAddress = *w.MemberAddress
		c.emptyMemberAddress = c.MemberAddress == ""
	}
	return nil
}

// canonicalCertificatePayload builds the canonical JSON for certificate signing.
// The payload must match exactly what the verifier reconstructs: the certificate
// JSON (minus signature) serialized with sorted keys, no whitespace, and native
// types (version as int, omitted empty optional fields).
type certificateScopeField string

const (
	certificateIdentityScopeField certificateScopeField = "identity_scope"
	certificateLifetimeField      certificateScopeField = "lifetime"
)

type certificatePayloadFields struct {
	CertificateID string
	TeamID        string
	TeamDIDKey    string
	MemberDIDKey  string
	MemberDIDAW   string
	MemberAddress string
	Alias         string
	Scope         string
	IssuedAt      string
	ScopeField    certificateScopeField
}

func canonicalCertificatePayload(certificate certificatePayloadFields) string {
	fields := map[string]any{
		"alias":                        certificate.Alias,
		"certificate_id":               certificate.CertificateID,
		"issued_at":                    certificate.IssuedAt,
		string(certificate.ScopeField): certificate.Scope,
		"member_did_key":               certificate.MemberDIDKey,
		"team_did_key":                 certificate.TeamDIDKey,
		"team_id":                      certificate.TeamID,
		"version":                      1,
	}
	if certificate.MemberAddress != "" {
		fields["member_address"] = certificate.MemberAddress
	}
	if certificate.MemberDIDAW != "" {
		fields["member_did_aw"] = certificate.MemberDIDAW
	}
	return canonicaljson.Object(fields)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// VerifyTeamCertificate checks the certificate signature against the team's
// public key. Returns nil if valid, an error describing the failure otherwise.
// It keeps its released signature and runs CheckDecodedTeamCertificate, the
// one strict check (version, required fields, portable values, subject and
// signature).
func VerifyTeamCertificate(cert *TeamCertificate, teamPub ed25519.PublicKey) error {
	if teamPub == nil {
		return fmt.Errorf("nil team public key")
	}
	return CheckDecodedTeamCertificate(cert, ComputeDIDKey(teamPub))
}
