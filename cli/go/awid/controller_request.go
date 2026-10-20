package awid

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SignAWIDControllerRequest signs the exact serialized body and external URL.
// The registry origin must be the configured or discovered origin, never a
// redirect destination. Claims carry the operation and its route parameters.
// Record, atomic-claim and DID-log signatures are separate protocols.
func SignAWIDControllerRequest(key ed25519.PrivateKey, method, requestURL string, body []byte, claims map[string]string, timestamp string) (map[string]string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("controller signing key is required")
	}
	target, err := url.Parse(requestURL)
	if err != nil || target.User != nil || target.Fragment != "" {
		return nil, fmt.Errorf("invalid registry request URL")
	}
	audience, err := CanonicalServerOrigin(target.Scheme + "://" + target.Host)
	if err != nil {
		return nil, err
	}
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	if target.RawQuery != "" || target.ForceQuery {
		path += "?" + target.RawQuery
	}
	hash := sha256.Sum256(body)
	payload := map[string]any{
		"v": 2, "type": "aweb.awid-controller-request", "aud": audience,
		"method": strings.ToUpper(method), "path": path,
		"body_sha256": hex.EncodeToString(hash[:]), "timestamp": timestamp,
	}
	for name, value := range claims {
		if _, reserved := payload[name]; reserved {
			return nil, fmt.Errorf("controller route claim %q is reserved", name)
		}
		payload[name] = value
	}
	canonical, err := CanonicalJSONValue(payload)
	if err != nil {
		return nil, err
	}
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	return map[string]string{
		"Authorization":         fmt.Sprintf("DIDKey %s %s", did, base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, []byte(canonical)))),
		"X-AWEB-Timestamp":      timestamp,
		"X-AWEB-Signed-Payload": base64.RawURLEncoding.EncodeToString([]byte(canonical)),
	}, nil
}

type controllerRequestAuth struct {
	key    ed25519.PrivateKey
	claims map[string]string
}

// ControllerRequest sends a covering controller mutation, including record
// publication and key rotation. It never follows redirects or retries in v1.
func (c *RegistryClient) ControllerRequest(ctx context.Context, method, registryURL, path string, claims map[string]string, key ed25519.PrivateKey, body any, out any) error {
	return c.requestControllerJSON(ctx, method, registryURL, path, controllerRequestAuth{key, claims}, body, out)
}

func (c *RegistryClient) requestControllerJSON(ctx context.Context, method, registryURL, path string, auth controllerRequestAuth, body any, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(registryURL) == "" {
		registryURL = c.defaultRegistryURL()
	}
	headers, err := SignAWIDControllerRequest(auth.key, method, strings.TrimRight(registryURL, "/")+path, data, auth.claims, c.now().Format(time.RFC3339))
	if err != nil {
		return err
	}
	var wire any
	if body != nil {
		wire = json.RawMessage(data)
	}
	return c.requestJSON(ctx, method, registryURL, path, headers, wire, out)
}

// ParentControllerHeaders keeps parent authority separate while binding the
// same request. Supply headers from SignAWIDControllerRequest with parent claims.
func ParentControllerHeaders(headers map[string]string) map[string]string {
	return map[string]string{
		"X-AWEB-Parent-Authorization":  headers["Authorization"],
		"X-AWEB-Parent-Timestamp":      headers["X-AWEB-Timestamp"],
		"X-AWEB-Parent-Signed-Payload": headers["X-AWEB-Signed-Payload"],
	}
}
