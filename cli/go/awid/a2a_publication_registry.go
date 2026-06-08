package awid

import (
	"context"
	"net/http"
	"strings"
)

type A2APublicationLookup struct {
	Address      RegistryAddress            `json:"address"`
	A2A          *A2APublicationLookupA2A   `json:"a2a,omitempty"`
	Verification A2APublicationVerification `json:"verification"`
}

type A2APublicationLookupA2A struct {
	CardURL              string `json:"card_url"`
	RPCURL               string `json:"rpc_url"`
	RouteID              string `json:"route_id"`
	CardDigest           string `json:"card_digest"`
	CardDigestAlg        string `json:"card_digest_alg,omitempty"`
	CardRevision         string `json:"card_revision,omitempty"`
	PublicationDigest    string `json:"publication_digest,omitempty"`
	PublicationID        string `json:"publication_id,omitempty"`
	PublicationSignerDID string `json:"publication_signer_did,omitempty"`
	PublicationSignerKID string `json:"publication_signer_kid,omitempty"`
	DelegationID         string `json:"delegation_id,omitempty"`
	DelegationDigest     string `json:"delegation_digest,omitempty"`
	GatewayDID           string `json:"gateway_did,omitempty"`
	GatewayKID           string `json:"gateway_kid,omitempty"`
	Status               string `json:"status,omitempty"`
	ExpiresAt            string `json:"expires_at,omitempty"`
}

type A2APublicationVerification struct {
	Status   string `json:"status"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Registry string `json:"registry,omitempty"`
}

func (c *RegistryClient) GetA2APublication(ctx context.Context, domain, name string) (*A2APublicationLookup, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.GetA2APublicationAt(ctx, registryURL, domain, name)
}

func (c *RegistryClient) GetA2APublicationAt(ctx context.Context, registryURL, domain, name string) (*A2APublicationLookup, string, error) {
	var out A2APublicationLookup
	path := "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/addresses/" + urlPathEscape(strings.TrimSpace(name)) + "/a2a"
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, "", err
	}
	return &out, registryURL, nil
}
