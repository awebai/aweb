package awid

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const RegistryCodeCertificateAlreadyRegistered = "certificate_already_registered"

// RegistryCodeTeamPrivate is the registry's machine-readable code for reads
// blocked by team visibility (awid_service/routes/teams.py
// TEAM_PRIVATE_ERROR_CODE). The CLI branches on it to explain the refusal;
// keep it in sync with the service.
const RegistryCodeTeamPrivate = "team_private"

// IsTeamPrivateError reports whether err is the registry's team_private
// visibility refusal. The parsed detail code is preferred; a 403 whose raw
// body carries the code is accepted as a fallback so a registry that answers
// with a differently shaped detail is still recognized.
func IsTeamPrivateError(err error) bool {
	var regErr *RegistryError
	if !errors.As(err, &regErr) || regErr.StatusCode != http.StatusForbidden {
		return false
	}
	return regErr.HasCode(RegistryCodeTeamPrivate) || strings.Contains(regErr.Detail, RegistryCodeTeamPrivate)
}

// RegistryTeam represents a team from the awid registry.
type RegistryTeam struct {
	TeamID      string `json:"team_id"`
	Domain      string `json:"domain"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	TeamDIDKey  string `json:"team_did_key"`
	Visibility  string `json:"visibility"`
	CreatedAt   string `json:"created_at"`
}

// RegistryCertificate represents a registered team membership certificate.
type RegistryCertificate struct {
	CertificateID string `json:"certificate_id"`
	TeamID        string `json:"team_id"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope"`
	IssuedAt      string `json:"issued_at"`
	RevokedAt     string `json:"revoked_at,omitempty"`
}

type registryCertificateFetchResponse struct {
	CertificateID string `json:"certificate_id"`
	TeamID        string `json:"team_id"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope"`
	IssuedAt      string `json:"issued_at"`
	RevokedAt     string `json:"revoked_at,omitempty"`
	Certificate   string `json:"certificate"`
}

type CertificateAlreadyRegisteredError struct {
	CertificateID string
	StatusCode    int
	Message       string
}

func (e *CertificateAlreadyRegisteredError) Error() string {
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = "Certificate already registered"
	}
	if strings.TrimSpace(e.CertificateID) == "" {
		return message
	}
	return fmt.Sprintf("%s: %s", message, strings.TrimSpace(e.CertificateID))
}

// TeamMemberReference resolves a (team_id, alias) reference to an active member.
type TeamMemberReference struct {
	TeamID        string `json:"team_id"`
	CertificateID string `json:"certificate_id"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope"`
	IssuedAt      string `json:"issued_at"`
}

type teamCreateRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	TeamDIDKey  string `json:"team_did_key"`
	Visibility  string `json:"visibility,omitempty"`
}

type teamVisibilityRequest struct {
	Visibility string `json:"visibility"`
}

type certificateRegisterRequest struct {
	CertificateID string `json:"certificate_id"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope"`
	Certificate   string `json:"certificate,omitempty"`
}

type certificateRevokeRequest struct {
	CertificateID string `json:"certificate_id"`
}

type certificateListResponse struct {
	Certificates []RegistryCertificate `json:"certificates"`
	HasMore      bool                  `json:"has_more"`
	NextCursor   string                `json:"next_cursor,omitempty"`
}

// certificateListPageLimit is the registry's MAX_LIMIT, the largest page it will
// serve. certificateListPageCap bounds the walk so a registry that never stops
// reporting more pages cannot spin here forever.
const (
	certificateListPageLimit = 200
	certificateListPageCap   = 500
)

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
			"name": name,
		}),
		teamCreateRequest{
			Name:        name,
			DisplayName: strings.TrimSpace(displayName),
			TeamDIDKey:  strings.TrimSpace(teamDIDKey),
			Visibility:  "private",
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetTeamVisibility updates a team's visibility metadata at awid.
// Auth: team controller DIDKey signature (using the team private key).
func (c *RegistryClient) SetTeamVisibility(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	visibility string,
	teamKey ed25519.PrivateKey,
) (*RegistryTeam, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	visibility = strings.TrimSpace(visibility)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if name == "" {
		return nil, fmt.Errorf("team name is required")
	}
	if visibility != "public" && visibility != "private" {
		return nil, fmt.Errorf("visibility must be 'public' or 'private'")
	}
	if teamKey == nil {
		return nil, fmt.Errorf("team signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/visibility"
	var out RegistryTeam
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		path,
		signedNamespaceHeaders(domain, "set_team_visibility", teamKey, map[string]string{
			"team_name":  name,
			"visibility": visibility,
		}),
		teamVisibilityRequest{Visibility: visibility},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTeam fetches team details from awid.
//
// signingKey is optional. When present the request carries the same
// path-signature the certificate blob fetch uses, which is what lets a team
// member or the team controller read a private team; nil keeps the request
// anonymous, which is enough for public teams and is the pre-visibility
// behavior byte for byte.
func (c *RegistryClient) GetTeam(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	signingKey ed25519.PrivateKey,
) (*RegistryTeam, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name)
	var out RegistryTeam
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, optionalSignedPathHeaders(http.MethodGet, path, signingKey), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteTeam removes a team after the caller has already revoked any active
// certificates. Auth: namespace controller DIDKey signature.
func (c *RegistryClient) DeleteTeam(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	controllerKey ed25519.PrivateKey,
	reason string,
) error {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if name == "" {
		return fmt.Errorf("team name is required")
	}
	if controllerKey == nil {
		return fmt.Errorf("controller signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name)
	var body any
	if strings.TrimSpace(reason) != "" {
		body = deleteReasonRequest{Reason: strings.TrimSpace(reason)}
	}
	return c.requestJSON(
		ctx,
		http.MethodDelete,
		registryURL,
		path,
		signedNamespaceHeaders(domain, "delete_team", controllerKey, map[string]string{
			"team_name": name,
		}),
		body,
		nil,
	)
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
	encodedCert, err := EncodeTeamCertificateHeader(cert)
	if err != nil {
		return fmt.Errorf("encode team certificate: %w", err)
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/certificates"
	if err := c.requestJSON(
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
			MemberDIDKey:  cert.MemberDIDKey,
			MemberDIDAW:   cert.MemberDIDAW,
			MemberAddress: cert.MemberAddress,
			Alias:         cert.Alias,
			IdentityScope: NormalizeIdentityScope(cert.IdentityScope),
			Certificate:   encodedCert,
		},
		nil,
	); err != nil {
		var registryErr *RegistryError
		if errors.As(err, &registryErr) && registryErr.StatusCode == http.StatusConflict && registryErr.HasCode(RegistryCodeCertificateAlreadyRegistered) {
			return &CertificateAlreadyRegisteredError{
				CertificateID: cert.CertificateID,
				StatusCode:    registryErr.StatusCode,
				Message:       registryErr.Message,
			}
		}
		return err
	}
	return nil
}

// FetchTeamCertificate downloads a signed team certificate blob from awid.
// Auth: the certificate subject's DIDKey signature, or another DID authorized
// by awid policy for this certificate.
func (c *RegistryClient) FetchTeamCertificate(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	certificateID string,
	signingKey ed25519.PrivateKey,
) (*TeamCertificate, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	certificateID = strings.TrimSpace(certificateID)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if name == "" {
		return nil, fmt.Errorf("team name is required")
	}
	if certificateID == "" {
		return nil, fmt.Errorf("certificate_id is required")
	}
	if signingKey == nil {
		return nil, fmt.Errorf("signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/certificates/" + urlPathEscape(certificateID)
	var out registryCertificateFetchResponse
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, signedPathHeaders(http.MethodGet, path, signingKey), nil, &out); err != nil {
		return nil, err
	}
	cert, err := DecodeTeamCertificateHeader(strings.TrimSpace(out.Certificate))
	if err != nil {
		return nil, fmt.Errorf("decode fetched certificate: %w", err)
	}
	if strings.TrimSpace(cert.CertificateID) != certificateID {
		return nil, fmt.Errorf("fetched certificate_id %q does not match requested %q", cert.CertificateID, certificateID)
	}
	if strings.TrimSpace(out.TeamID) != "" && strings.TrimSpace(cert.Team) != strings.TrimSpace(out.TeamID) {
		return nil, fmt.Errorf("fetched certificate team_id %q does not match response team_id %q", cert.Team, out.TeamID)
	}
	if did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); strings.TrimSpace(cert.MemberDIDKey) != did {
		return nil, fmt.Errorf("fetched certificate member_did_key %q does not match local signing key %q", cert.MemberDIDKey, did)
	}
	teamPub, err := ExtractPublicKey(strings.TrimSpace(cert.TeamDIDKey))
	if err != nil {
		return nil, fmt.Errorf("decode fetched certificate team_did_key: %w", err)
	}
	if err := VerifyTeamCertificate(cert, teamPub); err != nil {
		return nil, fmt.Errorf("verify fetched certificate: %w", err)
	}
	return cert, nil
}

// ListCertificates lists every certificate for a team, following the registry's
// pagination to the end. Callers read the result as a complete roster, so a
// listing that cannot be completed is returned as an error rather than as a
// short list that reads like the whole team.
//
// signingKey is optional; see GetTeam. Each page request is signed separately
// so a long walk never rides on a stale timestamp.
func (c *RegistryClient) ListCertificates(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	activeOnly bool,
	signingKey ed25519.PrivateKey,
) ([]RegistryCertificate, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	teamID := BuildTeamID(domain, name)
	basePath := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) +
		"/certificates?limit=" + itoa(certificateListPageLimit)
	if activeOnly {
		basePath += "&active_only=true"
	}

	var certificates []RegistryCertificate
	cursor := ""
	for page := 0; page < certificateListPageCap; page++ {
		path := basePath
		if cursor != "" {
			path += "&cursor=" + urlQueryEscape(cursor)
		}
		var out certificateListResponse
		if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, optionalSignedPathHeaders(http.MethodGet, path, signingKey), nil, &out); err != nil {
			return nil, err
		}
		certificates = append(certificates, out.Certificates...)
		if !out.HasMore {
			return certificates, nil
		}
		next := strings.TrimSpace(out.NextCursor)
		if next == "" {
			return nil, fmt.Errorf(
				"certificate listing for %s is truncated at %d: registry reports more certificates but returned no cursor to reach them",
				teamID, len(certificates))
		}
		if next == cursor {
			return nil, fmt.Errorf(
				"certificate listing for %s is truncated at %d: registry repeated cursor %q instead of advancing",
				teamID, len(certificates), next)
		}
		cursor = next
	}
	return nil, fmt.Errorf(
		"certificate listing for %s is truncated at %d: registry still reports more certificates after %d pages",
		teamID, len(certificates), certificateListPageCap)
}

// ResolveTeamMember resolves an active (team_id, alias) team-member reference.
//
// signingKey is optional; see GetTeam.
func (c *RegistryClient) ResolveTeamMember(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	alias string,
	signingKey ed25519.PrivateKey,
) (*TeamMemberReference, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	alias = strings.TrimSpace(alias)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if name == "" {
		return nil, fmt.Errorf("team name is required")
	}
	if alias == "" {
		return nil, fmt.Errorf("alias is required")
	}
	path := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/members/" + urlPathEscape(alias)
	var out TeamMemberReference
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, optionalSignedPathHeaders(http.MethodGet, path, signingKey), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
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
