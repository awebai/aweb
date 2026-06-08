package awid

import (
	"context"
	"net/http"
	"strings"
)

type A2APublicationLookup struct {
	Address string                   `json:"address"`
	DIDAW   string                   `json:"did_aw"`
	A2A     *A2APublicationLookupA2A `json:"a2a,omitempty"`
}

type A2APublicationLookupA2A struct {
	Status                 string `json:"status"`
	CardURL                string `json:"card_url"`
	RPCURL                 string `json:"rpc_url"`
	RouteID                string `json:"route_id"`
	Tenant                 string `json:"tenant,omitempty"`
	GatewayIdentity        string `json:"gateway_identity"`
	CardDigestAlg          string `json:"card_digest_alg"`
	CardDigest             string `json:"card_digest"`
	CardRevision           string `json:"card_revision"`
	PublicationAssertionID string `json:"publication_assertion_id"`
	DelegationID           string `json:"delegation_id,omitempty"`
	DelegationDigest       string `json:"delegation_digest,omitempty"`
	PublishedAt            string `json:"published_at"`
	ExpiresAt              string `json:"expires_at"`
	Verification           string `json:"verification"`
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
