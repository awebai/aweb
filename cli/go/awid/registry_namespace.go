package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type namespaceRegisterRequest struct {
	Domain        string `json:"domain"`
	ControllerDID string `json:"controller_did"`
}

type addressRegisterRequest struct {
	Name          string `json:"name"`
	DIDAW         string `json:"did_aw"`
	CurrentDIDKey string `json:"current_did_key"`
	Reachability  string `json:"reachability"`
}

func (c *RegistryClient) GetNamespaceAddress(ctx context.Context, domain, name string) (*RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.GetNamespaceAddressAt(ctx, registryURL, domain, name)
}

func (c *RegistryClient) GetNamespaceAddressAt(ctx context.Context, registryURL, domain, name string) (*RegistryAddress, string, error) {
	var out RegistryAddress
	path := "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/addresses/" + urlPathEscape(strings.TrimSpace(name))
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, "", err
	}
	return &out, registryURL, nil
}

func (c *RegistryClient) RegisterNamespace(
	ctx context.Context,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
) (*RegistryNamespace, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	namespace, err := c.RegisterNamespaceAt(ctx, registryURL, domain, controllerDID, signingKey)
	return namespace, registryURL, err
}

func (c *RegistryClient) RegisterNamespaceAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
) (*RegistryNamespace, error) {
	domain = canonicalizeDomain(domain)
	controllerDID = strings.TrimSpace(controllerDID)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if !strings.HasPrefix(controllerDID, "did:key:") {
		return nil, fmt.Errorf("controllerDID must start with did:key:")
	}
	if err := requireSigningKeyMatchesDID(signingKey, controllerDID); err != nil {
		return nil, err
	}

	var out RegistryNamespace
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		"/v1/namespaces",
		signedNamespaceHeaders(domain, "register", signingKey, nil),
		namespaceRegisterRequest{
			Domain:        domain,
			ControllerDID: controllerDID,
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) RegisterAddress(
	ctx context.Context,
	domain string,
	name string,
	didAW string,
	currentDIDKey string,
	reachability string,
	controllerSigningKey ed25519.PrivateKey,
) (*RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	address, err := c.RegisterAddressAt(ctx, registryURL, domain, name, didAW, currentDIDKey, reachability, controllerSigningKey)
	return address, registryURL, err
}

func (c *RegistryClient) RegisterAddressAt(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	didAW string,
	currentDIDKey string,
	reachability string,
	controllerSigningKey ed25519.PrivateKey,
) (*RegistryAddress, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	didAW = strings.TrimSpace(didAW)
	currentDIDKey = strings.TrimSpace(currentDIDKey)
	reachability = strings.TrimSpace(reachability)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if !strings.HasPrefix(didAW, "did:aw:") {
		return nil, fmt.Errorf("didAW must start with did:aw:")
	}
	if !strings.HasPrefix(currentDIDKey, "did:key:") {
		return nil, fmt.Errorf("currentDIDKey must start with did:key:")
	}
	if reachability == "" {
		reachability = "private"
	}
	if controllerSigningKey == nil {
		return nil, fmt.Errorf("controller signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/addresses"
	var out RegistryAddress
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		path,
		signedAddressHeaders(domain, name, "register_address", controllerSigningKey),
		addressRegisterRequest{
			Name:          name,
			DIDAW:         didAW,
			CurrentDIDKey: currentDIDKey,
			Reachability:  reachability,
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func requireSigningKeyMatchesDID(signingKey ed25519.PrivateKey, expectedDID string) error {
	if signingKey == nil {
		return fmt.Errorf("signing key is required")
	}
	actual := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if actual != strings.TrimSpace(expectedDID) {
		return fmt.Errorf("signing key does not match %s", strings.TrimSpace(expectedDID))
	}
	return nil
}

func signedNamespaceHeaders(
	domain string,
	operation string,
	signingKey ed25519.PrivateKey,
	extraPayload map[string]string,
) map[string]string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	fields := map[string]string{
		"domain":    canonicalizeDomain(domain),
		"operation": strings.TrimSpace(operation),
		"timestamp": timestamp,
	}
	for key, value := range extraPayload {
		fields[key] = strings.TrimSpace(value)
	}
	return signedCanonicalHeaders(fields, signingKey, timestamp)
}

func signedAddressHeaders(
	domain string,
	name string,
	operation string,
	signingKey ed25519.PrivateKey,
) map[string]string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	return signedCanonicalHeaders(map[string]string{
		"domain":    canonicalizeDomain(domain),
		"name":      strings.TrimSpace(name),
		"operation": strings.TrimSpace(operation),
		"timestamp": timestamp,
	}, signingKey, timestamp)
}

func signedCanonicalHeaders(fields map[string]string, signingKey ed25519.PrivateKey, timestamp string) map[string]string {
	did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	payload := canonicalRegistryJSON(fields)
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(payload)))
	return map[string]string{
		"Authorization":    fmt.Sprintf("DIDKey %s %s", did, signature),
		"X-AWEB-Timestamp": timestamp,
	}
}

func canonicalRegistryJSON(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteByte('{')
	for idx, key := range keys {
		if idx > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(key)
		b.WriteString(`":"`)
		writeEscapedString(&b, fields[key])
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}
