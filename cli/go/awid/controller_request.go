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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
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

// VerifyControllerRequestSignature checks a signer's answer over a covering-v2
// payload with the shared strict verifier, as the registry does: a valid
// signature by a valid key over exactly these bytes.
func VerifyControllerRequestSignature(didKey string, signature, payload []byte) error {
	return idStrictVerify(didKey, signature, func() ([]byte, error) { return payload, nil })
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
	chain, err := IDChainFromBundle(bundle)
	if err != nil {
		return nil, err
	}
	header, err := chain.Header()
	if err != nil {
		return nil, err
	}
	leaf := chain.Leaf()
	body := map[string]any{"certificate": leaf.Signed(), "expected_head": optionalText(expectedHead), "invitation_id": optionalText(invitationID)}
	var answer map[string]any
	err = c.controllerWrite(ctx, http.MethodPost, registryURL, "/v1/id-certificates/register", leaf.Domain(), "register_id_certificate", nil, body, signer, map[string]string{HeaderIDChain: header}, &answer)
	return answer, err
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
	var answer map[string]any
	err := c.controllerWrite(ctx, http.MethodPost, registryURL, "/v1/id-certificates/revoke", domain, "revoke_id_certificate", nil, body, signer, nil, &answer)
	return answer, err
}

// controllerWrite sends one controller write under a covering-v2 envelope:
// body (nil for none) is serialized once, as canonical JSON, and those bytes
// are both the ones signed and the ones sent. The signature names the
// destination registry's origin, the method, the request's escaped path and
// the body's hash, with the operation's claims. A signer that fails or answers
// with anything but a valid signature by a valid key over the exact payload
// sends nothing. There is no fallback to the legacy form.
func (c *RegistryClient) controllerWrite(ctx context.Context, method, registryURL, path, domain, operation string, claims map[string]any, body any, signer IDCertificateSigner, headers map[string]string, out any) error {
	// An empty registry URL is the client's default registry, as for every
	// other registry request.
	if strings.TrimSpace(registryURL) == "" {
		registryURL = c.defaultRegistryURL()
	}
	aud, err := CanonicalRegistryServerOrigin(registryURL)
	if err != nil {
		return err
	}
	var raw []byte
	if body != nil {
		if raw, err = sortedJSONBytes(body); err != nil {
			return err
		}
	}
	target, err := url.Parse(aud + path)
	if err != nil {
		return err
	}
	signedPath := target.EscapedPath()
	if target.RawQuery != "" {
		signedPath += "?" + target.RawQuery
	}
	timestamp := c.now().UTC().Format("2006-01-02T15:04:05Z")
	payload, err := ControllerRequestPayload(aud, method, signedPath, raw, timestamp, domain, operation, claims)
	if err != nil {
		return err
	}
	didKey, signature, err := signer(payload)
	if err != nil {
		return err
	}
	// The key is decoded strictly (ExtractPublicKey refuses degenerate keys).
	if err := idStrictVerify(didKey, signature, func() ([]byte, error) { return payload, nil }); err != nil {
		return fmt.Errorf("signer answer refused: %w", err)
	}
	signed := map[string]string{
		HeaderRequestTimestamp: timestamp,
		HeaderSignedPayload:    base64.RawURLEncoding.EncodeToString(payload),
		"Authorization":        "DIDKey " + didKey + " " + base64.RawStdEncoding.EncodeToString(signature),
	}
	for k, v := range headers {
		signed[k] = v
	}
	var sent atomic.Bool
	traced := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				sent.Store(true)
			}
		},
	})
	err = c.requestBytes(traced, method, aud, path, signed, raw, out)
	var answered *RegistryError
	if err != nil && sent.Load() && !errors.As(err, &answered) && !isReplaySafeRegistryRequest(method, path) {
		// The registry received the whole write and its answer was lost. aw
		// does not replay such a write, and the registry may have applied it.
		state := controllerWriteStates[operation]
		if state.write == "" {
			state = controllerWriteState{write: strings.ReplaceAll(operation, "_", " "), check: "aw id show"}
		}
		return &OutcomeUnknownError{err: err, write: state.write, check: state.check}
	}
	return err
}

// controllerWriteState names a controller write to the user and a command
// that reads the registry state it changes.
type controllerWriteState struct {
	write string
	check string
}

var controllerWriteStates = map[string]controllerWriteState{
	"create_team":             {"team create", "aw id team members"},
	"set_team_visibility":     {"team visibility change", "aw id team members"},
	"delete_team":             {"team delete", "aw id team members"},
	"rotate_team_key":         {"team key rotation", "aw id team members"},
	"register_certificate":    {"certificate registration", "aw id team members --include-revoked"},
	"revoke_certificate":      {"certificate revocation", "aw id team members --include-revoked"},
	"register_id_certificate": {"ID certificate registration", "aw id show"},
	"revoke_id_certificate":   {"ID certificate revocation", "aw id show"},
	"update_namespace":        {"namespace update", "aw id namespace <domain>"},
	"delete_namespace":        {"namespace delete", "aw id namespace <domain>"},
	"delete_address":          {"address delete", "aw id namespace addresses <domain>"},
}

func idBundleLeafDomain(bundle map[string]any) (string, error) {
	chain, err := IDChainFromBundle(bundle)
	if err != nil {
		return "", err
	}
	return chain.Leaf().Domain(), nil
}

func optionalText(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

// nullIfEmpty is value, or JSON null when it is empty.
func nullIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

// sortedJSONBytes is v as canonical JSON with every object's keys sorted,
// structs included: CanonicalJSONValue keeps a struct's declaration order, so
// v is first read back as generic JSON (numbers kept exact).
func sortedJSONBytes(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	encoded, err := CanonicalJSONValue(generic)
	if err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}
