package awid

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
)

// RegistryTeam represents a team from the awid registry.
type RegistryTeam struct {
	TeamID     string `json:"team_id"`
	Domain     string `json:"domain"`
	Name       string `json:"name"`
	TeamDIDKey string `json:"team_did_key"`
	CreatedAt  string `json:"created_at"`
}

// RegistryCertificate represents a registered team membership certificate.
type RegistryCertificate struct {
	CertificateID string `json:"certificate_id"`
	TeamAddress   string `json:"team_address"`
	MemberDIDKey  string `json:"member_did_key"`
	Alias         string `json:"alias"`
	Lifetime      string `json:"lifetime"`
	IssuedAt      string `json:"issued_at"`
	RevokedAt     string `json:"revoked_at,omitempty"`
}

type teamCreateRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	TeamDIDKey  string `json:"team_did_key"`
}

type certificateRegisterRequest struct {
	CertificateID string `json:"certificate_id"`
	TeamAddress   string `json:"team_address"`
	TeamDIDKey    string `json:"team_did_key"`
	MemberDIDKey  string `json:"member_did_key"`
	Alias         string `json:"alias"`
	Lifetime      string `json:"lifetime"`
	IssuedAt      string `json:"issued_at"`
	Signature     string `json:"signature"`
}

type certificateRevokeRequest struct {
	CertificateID string `json:"certificate_id"`
}

type certificateListResponse struct {
	Certificates []RegistryCertificate `json:"certificates"`
}

// CreateTeam registers a team under a namespace at awid.
// Auth: namespace controller DIDKey signature.
func (c *RegistryClient) CreateTeam(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	displayName string,
	teamDIDKey string,
	controllerKey ed25519.PrivateKey,
) (*RegistryTeam, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if name == "" {
		return nil, fmt.Errorf("team name is required")
	}
	if controllerKey == nil {
		return nil, fmt.Errorf("controller signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams"
	var out RegistryTeam
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		path,
		signedNamespaceHeaders(domain, "create_team", controllerKey, map[string]string{
			"team_name": name,
		}),
		teamCreateRequest{
			Name:        name,
			DisplayName: strings.TrimSpace(displayName),
			TeamDIDKey:  strings.TrimSpace(teamDIDKey),
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTeam fetches team details from awid.
func (c *RegistryClient) GetTeam(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
) (*RegistryTeam, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name)
	var out RegistryTeam
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegisterCertificate registers a team membership certificate at awid.
// Auth: team controller DIDKey signature (using the team private key).
func (c *RegistryClient) RegisterCertificate(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	cert *TeamCertificate,
	teamKey ed25519.PrivateKey,
) error {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	if cert == nil {
		return fmt.Errorf("certificate is required")
	}
	if teamKey == nil {
		return fmt.Errorf("team signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/certificates"
	return c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		path,
		signedNamespaceHeaders(domain, "register_certificate", teamKey, map[string]string{
			"team_name":      name,
			"certificate_id": cert.CertificateID,
		}),
		certificateRegisterRequest{
			CertificateID: cert.CertificateID,
			TeamAddress:   cert.TeamAddress,
			TeamDIDKey:    cert.TeamDIDKey,
			MemberDIDKey:  cert.MemberDIDKey,
			Alias:         cert.Alias,
			Lifetime:      cert.Lifetime,
			IssuedAt:      cert.IssuedAt,
			Signature:     cert.Signature,
		},
		nil,
	)
}

// ListCertificates lists certificates for a team.
func (c *RegistryClient) ListCertificates(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	activeOnly bool,
) ([]RegistryCertificate, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/certificates"
	if activeOnly {
		path += "?active_only=true"
	}
	var out certificateListResponse
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Certificates, nil
}

// RevokeCertificate revokes a team membership certificate at awid.
// Auth: team controller DIDKey signature (using the team private key).
func (c *RegistryClient) RevokeCertificate(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	certificateID string,
	teamKey ed25519.PrivateKey,
) error {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	certificateID = strings.TrimSpace(certificateID)
	if certificateID == "" {
		return fmt.Errorf("certificate_id is required")
	}
	if teamKey == nil {
		return fmt.Errorf("team signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/certificates/revoke"
	return c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		path,
		signedNamespaceHeaders(domain, "revoke_certificate", teamKey, map[string]string{
			"team_name":      name,
			"certificate_id": certificateID,
		}),
		certificateRevokeRequest{
			CertificateID: certificateID,
		},
		nil,
	)
}
