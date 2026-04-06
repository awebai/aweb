package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// TeamCertificate is a team membership proof signed by the team controller.
// The JSON representation is used for both file storage and the
// X-AWID-Team-Certificate HTTP header.
type TeamCertificate struct {
	Version       int    `json:"version"`
	CertificateID string `json:"certificate_id"`
	Team          string `json:"team"`
	TeamDIDKey    string `json:"team_did_key"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	Alias         string `json:"alias"`
	Lifetime      string `json:"lifetime"`
	IssuedAt      string `json:"issued_at"`
	Signature     string `json:"signature"`
}

// TeamCertificateFields are the inputs for signing a certificate.
type TeamCertificateFields struct {
	Team          string // team address (e.g. "acme.com/backend")
	MemberDIDKey  string
	MemberDIDAW   string // optional; from identity.yaml, empty for ephemeral
	MemberAddress string // optional; from identity.yaml, empty for ephemeral
	Alias         string
	Lifetime      string
}

// SignTeamCertificate creates and signs a team membership certificate
// using the team's Ed25519 private key.
func SignTeamCertificate(teamKey ed25519.PrivateKey, fields TeamCertificateFields) (*TeamCertificate, error) {
	if teamKey == nil {
		return nil, fmt.Errorf("team signing key is required")
	}
	if strings.TrimSpace(fields.Team) == "" {
		return nil, fmt.Errorf("team_address is required")
	}
	if strings.TrimSpace(fields.MemberDIDKey) == "" {
		return nil, fmt.Errorf("member_did_key is required")
	}
	if strings.TrimSpace(fields.Alias) == "" {
		return nil, fmt.Errorf("alias is required")
	}
	if strings.TrimSpace(fields.Lifetime) == "" {
		return nil, fmt.Errorf("lifetime is required")
	}

	certID, err := GenerateUUID4()
	if err != nil {
		return nil, err
	}
	teamDIDKey := ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	issuedAt := time.Now().UTC().Format(time.RFC3339)

	memberDIDAW := strings.TrimSpace(fields.MemberDIDAW)
	memberAddress := strings.TrimSpace(fields.MemberAddress)

	payload := canonicalCertificatePayload(certID, fields.Team, teamDIDKey, fields.MemberDIDKey, memberDIDAW, memberAddress, fields.Alias, fields.Lifetime, issuedAt)
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
		Lifetime:      fields.Lifetime,
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

	payload := canonicalCertificatePayload(
		cert.CertificateID,
		cert.Team,
		cert.TeamDIDKey,
		cert.MemberDIDKey,
		cert.MemberDIDAW,
		cert.MemberAddress,
		cert.Alias,
		cert.Lifetime,
		cert.IssuedAt,
	)

	if !ed25519.Verify(teamPub, []byte(payload), sig) {
		return fmt.Errorf("certificate signature verification failed")
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

// canonicalCertificatePayload builds the canonical JSON for certificate signing.
// The payload must match exactly what the verifier reconstructs: the certificate
// JSON (minus signature) serialized with sorted keys, no whitespace, and native
// types (version as int, omitted empty optional fields).
func canonicalCertificatePayload(certID, team, teamDIDKey, memberDIDKey, memberDIDAW, memberAddress, alias, lifetime, issuedAt string) string {
	type entry struct {
		key string
		val string // serialized JSON value (already quoted for strings)
	}

	entries := []entry{
		{"alias", jsonString(alias)},
		{"certificate_id", jsonString(certID)},
		{"issued_at", jsonString(issuedAt)},
		{"lifetime", jsonString(lifetime)},
	}
	if memberAddress != "" {
		entries = append(entries, entry{"member_address", jsonString(memberAddress)})
	}
	if memberDIDAW != "" {
		entries = append(entries, entry{"member_did_aw", jsonString(memberDIDAW)})
	}
	entries = append(entries,
		entry{"member_did_key", jsonString(memberDIDKey)},
		entry{"team", jsonString(team)},
		entry{"team_did_key", jsonString(teamDIDKey)},
		entry{"version", "1"},
	)

	// Keys are already in sorted order by construction above.
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
