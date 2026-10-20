package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"
)

type CertificateStatus struct {
	TeamID                  string  `json:"team_id"`
	TeamDIDKey              string  `json:"team_did_key"`
	Status                  string  `json:"status"`
	RevokedAt               *string `json:"revoked_at"`
	ReplacedByCertificateID string  `json:"replaced_by_certificate_id"`
}

func (c *RegistryClient) GetCertificateStatus(ctx context.Context, registryURL, domain, name, id string) (*CertificateStatus, error) {
	var out CertificateStatus
	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/certificates/" + urlPathEscape(id) + "/status?include_replacement=true"
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, err
	}
	if out.TeamID != BuildTeamID(domain, name) || (out.Status != "active" && out.Status != "revoked") {
		return nil, fmt.Errorf("invalid certificate status")
	}
	if _, err := ExtractPublicKey(out.TeamDIDKey); err != nil {
		return nil, err
	}
	return &out, nil
}

// FetchCurrentCertificate verifies the public artifact under the registry's
// current team key, never the key asserted solely by the fetched blob.
func (c *RegistryClient) FetchCurrentCertificate(ctx context.Context, registryURL, domain, name, id string, memberKey ed25519.PrivateKey) (*TeamCertificate, error) {
	status, err := c.GetCertificateStatus(ctx, registryURL, domain, name, id)
	if err != nil {
		return nil, err
	}
	if status.Status != "active" {
		return nil, fmt.Errorf("certificate_revoked: replacement is inactive")
	}
	cert, err := c.FetchTeamCertificate(ctx, registryURL, domain, name, id, memberKey)
	if err != nil {
		return nil, err
	}
	if cert.Team != BuildTeamID(domain, name) || cert.MemberDIDKey != ComputeDIDKey(memberKey.Public().(ed25519.PublicKey)) || cert.TeamDIDKey != status.TeamDIDKey {
		return nil, fmt.Errorf("replacement certificate binding mismatch")
	}
	pub, err := ExtractPublicKey(status.TeamDIDKey)
	if err != nil {
		return nil, err
	}
	if err := VerifyTeamCertificate(cert, pub); err != nil {
		return nil, err
	}
	return cert, nil
}

func (c *RegistryClient) RolloverCertificate(ctx context.Context, registryURL, domain, name, oldID string, replacement *TeamCertificate, teamKey ed25519.PrivateKey) error {
	header, err := EncodeTeamCertificateHeader(replacement)
	if err != nil {
		return err
	}
	body := map[string]any{"replacement": certificateRegisterRequest{
		CertificateID: replacement.CertificateID, MemberDIDKey: replacement.MemberDIDKey,
		MemberDIDAW: replacement.MemberDIDAW, MemberAddress: replacement.MemberAddress,
		Alias: replacement.Alias, IdentityScope: replacement.IdentityScope, Certificate: header,
	}}
	return c.ControllerRequest(ctx, http.MethodPost, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/teams/"+urlPathEscape(name)+"/certificates/"+urlPathEscape(oldID)+"/rollover",
		map[string]string{"operation": "rollover_certificate", "domain": domain, "team_name": name, "certificate_id": oldID, "replacement_certificate_id": replacement.CertificateID}, teamKey, body, nil)
}

// GetTeamCredentialPolicy verifies the signed policy against the current key
// returned by the configured registry, not a key asserted only in the record.
func (c *RegistryClient) GetTeamCredentialPolicy(ctx context.Context, registryURL, domain, name string) (map[string]any, error) {
	var wire map[string]json.RawMessage
	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/credential-lifetimes"
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &wire); err != nil {
		return nil, err
	}
	if _, ok := wire["record"]; !ok {
		return nil, fmt.Errorf("malformed credential policy response")
	}
	if _, ok := wire["signature"]; !ok {
		return nil, fmt.Errorf("malformed credential policy response")
	}
	var teamID, teamKey string
	if json.Unmarshal(wire["team_id"], &teamID) != nil || teamID != BuildTeamID(domain, name) || json.Unmarshal(wire["team_did_key"], &teamKey) != nil {
		return nil, fmt.Errorf("credential policy team mismatch")
	}
	pub, err := ExtractPublicKey(teamKey)
	if err != nil {
		return nil, err
	}
	if string(wire["record"]) == "null" && string(wire["signature"]) == "null" {
		return nil, nil
	}
	var record map[string]any
	var signature string
	if json.Unmarshal(wire["record"], &record) != nil || json.Unmarshal(wire["signature"], &signature) != nil || len(record) != 10 {
		return nil, fmt.Errorf("malformed credential policy")
	}
	if record["v"] != float64(1) || record["type"] != "aweb.team-credential-policy" || record["team_id"] != teamID || record["team_did_key"] != teamKey {
		return nil, fmt.Errorf("credential policy binding mismatch")
	}
	for _, field := range []string{"member_certificate", "ephemeral_certificate", "identity_grant", "hosted_mcp_grant"} {
		value, present := record[field]
		if !present {
			return nil, fmt.Errorf("missing credential policy maximum")
		}
		if value != nil {
			n, ok := value.(float64)
			if !ok || n < 1 || n > math.MaxInt32 || math.Trunc(n) != n {
				return nil, fmt.Errorf("invalid credential policy maximum")
			}
		}
	}
	revision, ok := record["revision"].(float64)
	if !ok || revision < 1 || revision > 9007199254740991 || math.Trunc(revision) != revision {
		return nil, fmt.Errorf("invalid credential policy revision")
	}
	issued, ok := record["issued_at"].(string)
	when, timeErr := time.Parse("2006-01-02T15:04:05Z", issued)
	if !ok || timeErr != nil || when.After(time.Now().Add(5*time.Minute)) {
		return nil, fmt.Errorf("invalid credential policy issued_at")
	}
	canonical, err := CanonicalJSONValue(record)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawStdEncoding.Strict().DecodeString(signature)
	if err != nil || !ed25519.Verify(pub, []byte("aweb.team-credential-policy/1\n"+canonical), sig) {
		return nil, fmt.Errorf("invalid credential policy signature")
	}
	return record, nil
}

func (c *RegistryClient) SetTeamCredentialPolicy(ctx context.Context, registryURL, domain, name string, record map[string]any, teamKey ed25519.PrivateKey) error {
	canonical, err := CanonicalJSONValue(record)
	if err != nil {
		return err
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, []byte("aweb.team-credential-policy/1\n"+canonical)))
	return c.ControllerRequest(ctx, http.MethodPost, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/teams/"+urlPathEscape(name)+"/credential-lifetimes",
		map[string]string{"operation": "set_credential_lifetimes", "domain": domain, "team_name": name}, teamKey,
		map[string]any{"record": record, "signature": signature}, nil)
}
