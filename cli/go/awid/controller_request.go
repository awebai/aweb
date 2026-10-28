package awid

// Covering-v2 AWID controller requests (docs/awid-controller-requests.md) and
// the identity-tree writes that use them: register and revoke. The signer
// answers for the exact payload bytes; its answer is verified under the ID
// Ed25519 profile before anything is sent.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const controllerRequestType = "aweb.awid-controller-request"

// ControllerRequestPayload is the canonical covering-v2 payload for one HTTP
// request: the binding fields plus the operation's own claims.
func ControllerRequestPayload(aud, method, path string, body []byte, timestamp, domain, operation string, claims map[string]any) ([]byte, error) {
	sum := sha256.Sum256(body)
	payload := map[string]any{}
	for k, v := range claims {
		payload[k] = v
	}
	for k, v := range map[string]any{
		"v": 2, "type": controllerRequestType, "aud": aud, "method": strings.ToUpper(method), "path": path,
		"body_sha256": hex.EncodeToString(sum[:]), "timestamp": timestamp, "domain": domain, "operation": operation,
	} {
		payload[k] = v
	}
	raw, err := CanonicalJSONValue(payload)
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

// RegisterIDCertificate registers bundle's leaf at its domain's registry,
// with the bundle as its supporting chain. signer holds the subject's
// current key.
func (c *RegistryClient) RegisterIDCertificate(ctx context.Context, bundle map[string]any, signer IDCertificateSigner, expectedHead, invitationID *string) (map[string]any, error) {
	domain, err := idBundleLeafDomain(bundle)
	if err != nil {
		return nil, err
	}
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, err
	}
	return c.RegisterIDCertificateAt(ctx, registryURL, bundle, signer, expectedHead, invitationID)
}

// RegisterIDCertificateAt registers at an explicit registry origin.
func (c *RegistryClient) RegisterIDCertificateAt(ctx context.Context, registryURL string, bundle map[string]any, signer IDCertificateSigner, expectedHead, invitationID *string) (map[string]any, error) {
	domain, err := idBundleLeafDomain(bundle)
	if err != nil {
		return nil, err
	}
	header, err := EncodeIDChainHeader(bundle)
	if err != nil {
		return nil, err
	}
	certificates := bundle["certificates"].([]any)
	body := map[string]any{"certificate": certificates[len(certificates)-1], "expected_head": optionalText(expectedHead), "invitation_id": optionalText(invitationID)}
	return c.coveringRequest(ctx, registryURL, "/v1/id-certificates/register", domain, "register_id_certificate", body, signer, map[string]string{"X-AWID-ID-Chain": header})
}

// RevokeIDCertificate revokes the registered id; the registry decides
// whether the signer acts as root, self or parent.
func (c *RegistryClient) RevokeIDCertificate(ctx context.Context, domain, id string, signer IDCertificateSigner, expectedHead, effectiveFrom *string) (map[string]any, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, err
	}
	return c.RevokeIDCertificateAt(ctx, registryURL, domain, id, signer, expectedHead, effectiveFrom)
}

// RevokeIDCertificateAt revokes at an explicit registry origin.
func (c *RegistryClient) RevokeIDCertificateAt(ctx context.Context, registryURL, domain, id string, signer IDCertificateSigner, expectedHead, effectiveFrom *string) (map[string]any, error) {
	body := map[string]any{"domain": domain, "id": id, "expected_head": optionalText(expectedHead), "effective_from": optionalText(effectiveFrom)}
	return c.coveringRequest(ctx, registryURL, "/v1/id-certificates/revoke", domain, "revoke_id_certificate", body, signer, nil)
}

// coveringRequest POSTs body under a covering-v2 envelope. A signer that
// fails or answers with anything but a valid signature by a valid key over
// the exact payload sends nothing.
func (c *RegistryClient) coveringRequest(ctx context.Context, registryURL, path, domain, operation string, body map[string]any, signer IDCertificateSigner, headers map[string]string) (map[string]any, error) {
	// The audience is the registry's origin; the request goes to the routed
	// registry URL, which may sit under a path prefix.
	routed, err := url.Parse(strings.TrimSpace(registryURL))
	if err != nil {
		return nil, err
	}
	aud, err := canonicalServerOrigin((&url.URL{Scheme: routed.Scheme, Host: routed.Host}).String())
	if err != nil {
		return nil, err
	}
	raw, err := CanonicalJSONValue(body)
	if err != nil {
		return nil, err
	}
	timestamp := c.now().Format("2006-01-02T15:04:05Z")
	payload, err := ControllerRequestPayload(aud, http.MethodPost, path, []byte(raw), timestamp, domain, operation, nil)
	if err != nil {
		return nil, err
	}
	didKey, signature, err := signer(payload)
	if err != nil {
		return nil, err
	}
	// The key is decoded strictly (ExtractPublicKey refuses degenerate keys).
	if len(signature) != 64 {
		return nil, fmt.Errorf("signer answer refused: invalid_signature")
	}
	if err := idStrictVerify(didKey, signature, func() ([]byte, error) { return payload, nil }); err != nil {
		return nil, fmt.Errorf("signer answer refused: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(routed.String(), "/")+path, bytes.NewReader([]byte(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-AWEB-Timestamp", timestamp)
	req.Header.Set("X-AWEB-Signed-Payload", base64.RawURLEncoding.EncodeToString(payload))
	req.Header.Set("Authorization", "DIDKey "+didKey+" "+base64.RawStdEncoding.EncodeToString(signature))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	setUserAgent(req, "")
	resp, err := DoNoRedirectWithTimeout(c.httpClient(), req, APITimeout())
	if err != nil {
		return nil, err
	}
	var answer map[string]any
	if err := decodeRegistryResponse(resp, &answer); err != nil {
		return nil, err
	}
	return answer, nil
}

func idBundleLeafDomain(bundle map[string]any) (string, error) {
	if err := idCertificateBundleShape(bundle); err != nil {
		return "", err
	}
	certificates := bundle["certificates"].([]any)
	leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
	return leaf["domain"].(string), nil
}

func optionalText(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
