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
	Domain                string `json:"domain"`
	ControllerDID         string `json:"controller_did"`
	DefaultDeliveryOrigin string `json:"default_delivery_origin,omitempty"`
}

type namespaceUpdateRequest struct {
	DefaultDeliveryOrigin string `json:"default_delivery_origin"`
}

type addressRegisterRequest struct {
	Name          string `json:"name"`
	DIDAW         string `json:"did_aw"`
	CurrentDIDKey string `json:"current_did_key"`
}

type AtomicAddressClaimParams struct {
	Domain                        string
	AddressName                   string
	DIDAW                         string
	CurrentDIDKey                 string
	IdentitySigningKey            ed25519.PrivateKey
	NamespaceControllerSigningKey ed25519.PrivateKey
	DryRun                        bool
	IdentityCustody               string
	NamespaceCustody              string
}

type atomicAddressClaimRequest struct {
	Operation          string                 `json:"operation"`
	AddressName        string                 `json:"address_name"`
	DIDAW              string                 `json:"did_aw"`
	CurrentDIDKey      string                 `json:"current_did_key"`
	RegistryURL        string                 `json:"registry_url"`
	Timestamp          string                 `json:"timestamp"`
	DryRun             bool                   `json:"dry_run"`
	IdentityCustody    string                 `json:"identity_custody"`
	NamespaceCustody   string                 `json:"namespace_custody"`
	IdentitySignature  string                 `json:"identity_signature"`
	NamespaceSignature string                 `json:"namespace_signature"`
	DIDLogProof        atomicClaimDIDLogProof `json:"did_log_proof"`
}

type atomicClaimDIDLogProof struct {
	DIDAW          string  `json:"did_aw"`
	Seq            int     `json:"seq"`
	Operation      string  `json:"operation"`
	PreviousDIDKey *string `json:"previous_did_key"`
	NewDIDKey      string  `json:"new_did_key"`
	PrevEntryHash  *string `json:"prev_entry_hash"`
	StateHash      string  `json:"state_hash"`
	AuthorizedBy   string  `json:"authorized_by"`
	Timestamp      string  `json:"timestamp"`
	Signature      string  `json:"signature"`
}

type AtomicAddressClaimResult struct {
	Status           string           `json:"status"`
	DryRun           bool             `json:"dry_run"`
	Domain           string           `json:"domain"`
	Name             string           `json:"name"`
	DIDAW            string           `json:"did_aw"`
	CurrentDIDKey    string           `json:"current_did_key"`
	IdentityCustody  string           `json:"identity_custody"`
	NamespaceCustody string           `json:"namespace_custody"`
	DIDStatus        string           `json:"did_status"`
	AddressStatus    string           `json:"address_status"`
	Address          *RegistryAddress `json:"address,omitempty"`
}

type deleteReasonRequest struct {
	Reason string `json:"reason,omitempty"`
}

type NamespaceReverifyResult struct {
	NamespaceID        string `json:"namespace_id"`
	Domain             string `json:"domain"`
	ControllerDID      string `json:"controller_did,omitempty"`
	VerificationStatus string `json:"verification_status"`
	LastVerifiedAt     string `json:"last_verified_at,omitempty"`
	CreatedAt          string `json:"created_at"`
	OldControllerDID   string `json:"old_controller_did,omitempty"`
	NewControllerDID   string `json:"new_controller_did,omitempty"`
}

func (c *RegistryClient) GetNamespaceAddress(ctx context.Context, domain, name string) (*RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.GetNamespaceAddressAt(ctx, registryURL, domain, name)
}

func (c *RegistryClient) GetNamespaceAddressSigned(
	ctx context.Context,
	domain, name string,
	signingKey ed25519.PrivateKey,
) (*RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.GetNamespaceAddressAtSigned(ctx, registryURL, domain, name, signingKey)
}

func (c *RegistryClient) GetNamespaceAddressAt(ctx context.Context, registryURL, domain, name string) (*RegistryAddress, string, error) {
	var out RegistryAddress
	path := "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/addresses/" + urlPathEscape(strings.TrimSpace(name))
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, "", err
	}
	return &out, registryURL, nil
}

func (c *RegistryClient) GetNamespaceAddressAtSigned(
	ctx context.Context,
	registryURL, domain, name string,
	signingKey ed25519.PrivateKey,
) (*RegistryAddress, string, error) {
	return c.GetNamespaceAddressAt(ctx, registryURL, domain, name)
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

func (c *RegistryClient) RegisterNamespaceWithDeliveryOrigin(
	ctx context.Context,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
	defaultDeliveryOrigin string,
) (*RegistryNamespace, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	namespace, err := c.RegisterNamespaceWithDeliveryOriginAt(ctx, registryURL, domain, controllerDID, signingKey, defaultDeliveryOrigin)
	return namespace, registryURL, err
}

func (c *RegistryClient) RegisterNamespaceAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
) (*RegistryNamespace, error) {
	return c.RegisterNamespaceWithDeliveryOriginAt(ctx, registryURL, domain, controllerDID, signingKey, "")
}

func (c *RegistryClient) RegisterNamespaceWithDeliveryOriginAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
	defaultDeliveryOrigin string,
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
	defaultDeliveryOrigin = strings.TrimSpace(defaultDeliveryOrigin)
	extraPayload := map[string]string(nil)
	if defaultDeliveryOrigin != "" {
		canonicalOrigin, err := CanonicalServerOrigin(defaultDeliveryOrigin)
		if err != nil {
			return nil, fmt.Errorf("default delivery origin: %w", err)
		}
		defaultDeliveryOrigin = canonicalOrigin
		extraPayload = map[string]string{"default_delivery_origin": defaultDeliveryOrigin}
	}

	var out RegistryNamespace
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		"/v1/namespaces",
		signedNamespaceHeaders(domain, "register", signingKey, extraPayload),
		namespaceRegisterRequest{
			Domain:                domain,
			ControllerDID:         controllerDID,
			DefaultDeliveryOrigin: defaultDeliveryOrigin,
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) UpdateNamespaceDeliveryOrigin(
	ctx context.Context,
	domain string,
	controllerSigningKey ed25519.PrivateKey,
	deliveryOrigin string,
) (*RegistryNamespace, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	namespace, err := c.UpdateNamespaceDeliveryOriginAt(ctx, registryURL, domain, controllerSigningKey, deliveryOrigin)
	return namespace, registryURL, err
}

func (c *RegistryClient) UpdateNamespaceDeliveryOriginAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerSigningKey ed25519.PrivateKey,
	deliveryOrigin string,
) (*RegistryNamespace, error) {
	domain = canonicalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if controllerSigningKey == nil {
		return nil, fmt.Errorf("controller signing key is required")
	}
	canonicalOrigin, err := CanonicalServerOrigin(deliveryOrigin)
	if err != nil {
		return nil, fmt.Errorf("delivery origin: %w", err)
	}

	var out RegistryNamespace
	if err := c.requestJSON(
		ctx,
		http.MethodPatch,
		registryURL,
		"/v1/namespaces/"+urlPathEscape(domain),
		signedNamespaceHeaders(
			domain,
			"update_namespace",
			controllerSigningKey,
			map[string]string{"default_delivery_origin": canonicalOrigin},
		),
		namespaceUpdateRequest{DefaultDeliveryOrigin: canonicalOrigin},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) DeleteNamespace(
	ctx context.Context,
	domain string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) (string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return "", err
	}
	return registryURL, c.DeleteNamespaceAt(ctx, registryURL, domain, controllerSigningKey, reason)
}

func (c *RegistryClient) DeleteNamespaceAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) error {
	domain = canonicalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if controllerSigningKey == nil {
		return fmt.Errorf("controller signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain)
	var body any
	if strings.TrimSpace(reason) != "" {
		body = deleteReasonRequest{Reason: strings.TrimSpace(reason)}
	}
	return c.requestJSON(
		ctx,
		http.MethodDelete,
		registryURL,
		path,
		signedNamespaceHeaders(domain, "delete_namespace", controllerSigningKey, nil),
		body,
		nil,
	)
}

func (c *RegistryClient) ReverifyNamespaceAt(
	ctx context.Context,
	registryURL string,
	domain string,
) (*NamespaceReverifyResult, error) {
	domain = canonicalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	var out NamespaceReverifyResult
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/reverify",
		nil,
		nil,
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
	controllerSigningKey ed25519.PrivateKey,
) (*RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	address, err := c.RegisterAddressAt(ctx, registryURL, domain, name, didAW, currentDIDKey, controllerSigningKey)
	return address, registryURL, err
}

func (c *RegistryClient) RegisterAddressAt(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	didAW string,
	currentDIDKey string,
	controllerSigningKey ed25519.PrivateKey,
) (*RegistryAddress, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	didAW = strings.TrimSpace(didAW)
	currentDIDKey = strings.TrimSpace(currentDIDKey)
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
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) ClaimIdentityAddressAt(
	ctx context.Context,
	registryURL string,
	params AtomicAddressClaimParams,
) (*AtomicAddressClaimResult, error) {
	registryURL, err := canonicalRegistryServerOrigin(registryURL)
	if err != nil {
		return nil, fmt.Errorf("registry_url: %w", err)
	}
	params.Domain = canonicalizeDomain(params.Domain)
	params.AddressName = strings.ToLower(strings.TrimSpace(params.AddressName))
	params.DIDAW = strings.TrimSpace(params.DIDAW)
	params.CurrentDIDKey = strings.TrimSpace(params.CurrentDIDKey)
	if params.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if params.AddressName == "" {
		return nil, fmt.Errorf("address name is required")
	}
	if !strings.HasPrefix(params.DIDAW, "did:aw:") {
		return nil, fmt.Errorf("did_aw must start with did:aw:")
	}
	if !strings.HasPrefix(params.CurrentDIDKey, "did:key:") {
		return nil, fmt.Errorf("current_did_key must start with did:key:")
	}
	if params.IdentitySigningKey == nil {
		return nil, fmt.Errorf("identity signing key is required")
	}
	if params.NamespaceControllerSigningKey == nil {
		return nil, fmt.Errorf("namespace controller signing key is required")
	}
	if did := ComputeDIDKey(params.IdentitySigningKey.Public().(ed25519.PublicKey)); did != params.CurrentDIDKey {
		return nil, fmt.Errorf("identity signing key does not match current_did_key")
	}
	if stableID := ComputeStableID(params.IdentitySigningKey.Public().(ed25519.PublicKey)); stableID != params.DIDAW {
		return nil, fmt.Errorf("identity signing key does not match did_aw")
	}
	identityCustody := strings.TrimSpace(params.IdentityCustody)
	if identityCustody == "" {
		identityCustody = string(AddressClaimCustodySelf)
	}
	namespaceCustody := strings.TrimSpace(params.NamespaceCustody)
	if namespaceCustody == "" {
		namespaceCustody = string(AddressClaimCustodySelf)
	}

	timestamp := registryNow().UTC().Format(time.RFC3339)
	fields := AtomicAddressClaimFields{
		Operation:        AtomicAddressClaimOperation,
		Domain:           params.Domain,
		AddressName:      params.AddressName,
		DIDAW:            params.DIDAW,
		CurrentDIDKey:    params.CurrentDIDKey,
		RegistryURL:      registryURL,
		Timestamp:        timestamp,
		DryRun:           params.DryRun,
		IdentityCustody:  identityCustody,
		NamespaceCustody: namespaceCustody,
	}
	identityCanonical, err := AtomicAddressClaimIdentityCanonical(fields)
	if err != nil {
		return nil, err
	}
	identitySignature := base64.RawStdEncoding.EncodeToString(
		ed25519.Sign(params.IdentitySigningKey, []byte(identityCanonical)),
	)
	identityProofHash, err := AtomicAddressClaimIdentityProofHash(identityCanonical, identitySignature)
	if err != nil {
		return nil, err
	}
	namespaceCanonical, err := AtomicAddressClaimNamespaceCanonical(fields, identityProofHash)
	if err != nil {
		return nil, err
	}
	namespaceSignature := base64.RawStdEncoding.EncodeToString(
		ed25519.Sign(params.NamespaceControllerSigningKey, []byte(namespaceCanonical)),
	)

	stateHash := stableIdentityStateHash(params.DIDAW, params.CurrentDIDKey)
	didLogPayload := CanonicalDidLogPayload(params.DIDAW, &DidKeyEvidence{
		Seq:            1,
		Operation:      "register_did",
		PreviousDIDKey: nil,
		NewDIDKey:      params.CurrentDIDKey,
		PrevEntryHash:  nil,
		StateHash:      stateHash,
		AuthorizedBy:   params.CurrentDIDKey,
		Timestamp:      timestamp,
	})
	body := atomicAddressClaimRequest{
		Operation:          AtomicAddressClaimOperation,
		AddressName:        params.AddressName,
		DIDAW:              params.DIDAW,
		CurrentDIDKey:      params.CurrentDIDKey,
		RegistryURL:        registryURL,
		Timestamp:          timestamp,
		DryRun:             params.DryRun,
		IdentityCustody:    identityCustody,
		NamespaceCustody:   namespaceCustody,
		IdentitySignature:  identitySignature,
		NamespaceSignature: namespaceSignature,
		DIDLogProof: atomicClaimDIDLogProof{
			DIDAW:          params.DIDAW,
			Seq:            1,
			Operation:      "register_did",
			PreviousDIDKey: nil,
			NewDIDKey:      params.CurrentDIDKey,
			PrevEntryHash:  nil,
			StateHash:      stateHash,
			AuthorizedBy:   params.CurrentDIDKey,
			Timestamp:      timestamp,
			Signature: base64.RawStdEncoding.EncodeToString(
				ed25519.Sign(params.IdentitySigningKey, []byte(didLogPayload)),
			),
		},
	}

	path := "/v1/namespaces/" + urlPathEscape(params.Domain) + "/addresses/claims"
	var out AtomicAddressClaimResult
	if err := c.requestJSON(ctx, http.MethodPost, registryURL, path, nil, body, &out); err != nil {
		return nil, atomicAddressClaimConflictFromError(err)
	}
	return &out, nil
}

func (c *RegistryClient) DeleteAddress(
	ctx context.Context,
	domain string,
	name string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) (string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return "", err
	}
	return registryURL, c.DeleteAddressAt(ctx, registryURL, domain, name, controllerSigningKey, reason)
}

func (c *RegistryClient) DeleteAddressAt(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) error {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if controllerSigningKey == nil {
		return fmt.Errorf("controller signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/addresses/" + urlPathEscape(name)
	var body any
	if strings.TrimSpace(reason) != "" {
		body = deleteReasonRequest{Reason: strings.TrimSpace(reason)}
	}
	return c.requestJSON(
		ctx,
		http.MethodDelete,
		registryURL,
		path,
		signedAddressHeaders(domain, name, "delete_address", controllerSigningKey),
		body,
		nil,
	)
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
