package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

type RegistryError struct {
	StatusCode int
	Detail     string
	Code       string
	Message    string
}

func (e *RegistryError) Error() string {
	if strings.TrimSpace(e.Detail) == "" {
		return fmt.Sprintf("registry http %d", e.StatusCode)
	}
	return fmt.Sprintf("registry http %d: %s", e.StatusCode, e.Detail)
}

type AlreadyRegisteredError struct {
	DIDAW          string
	ExistingDIDKey string
}

func (e *AlreadyRegisteredError) Error() string {
	return fmt.Sprintf("did:aw %s is already registered to %s", e.DIDAW, e.ExistingDIDKey)
}

type DIDMapping struct {
	DIDAW         string    `json:"did_aw"`
	CurrentDIDKey string    `json:"current_did_key"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type RegistryNamespace struct {
	NamespaceID           string `json:"namespace_id"`
	Domain                string `json:"domain"`
	ControllerDID         string `json:"controller_did,omitempty"`
	VerificationStatus    string `json:"verification_status"`
	DefaultDeliveryOrigin string `json:"default_delivery_origin,omitempty"`
	LastVerifiedAt        string `json:"last_verified_at,omitempty"`
	CreatedAt             string `json:"created_at"`
}

type RegistryDelivery struct {
	Origin string `json:"origin,omitempty"`
	Source string `json:"source,omitempty"`
}

type RegistryAddress struct {
	AddressID       string            `json:"address_id"`
	Domain          string            `json:"domain"`
	Name            string            `json:"name"`
	DIDAW           string            `json:"did_aw"`
	CurrentDIDKey   string            `json:"current_did_key"`
	Reachability    string            `json:"reachability"`
	VisibleToTeamID *string           `json:"visible_to_team_id,omitempty"`
	Delivery        *RegistryDelivery `json:"delivery,omitempty"`
	CreatedAt       string            `json:"created_at"`
}

type RegistryAddressList struct {
	Addresses []RegistryAddress `json:"addresses"`
}

type RegistryClient struct {
	DefaultRegistryURL string
	Resolver           *RegistryResolver
	HTTPClient         *http.Client
	RequestID          string
}

const registryTransientMaxRetries = 3

var registryNow = func() time.Time { return time.Now().UTC() }

type didUpdateRequest struct {
	Operation     string `json:"operation"`
	NewDIDKey     string `json:"new_did_key"`
	Seq           int    `json:"seq"`
	PrevEntryHash string `json:"prev_entry_hash"`
	StateHash     string `json:"state_hash"`
	AuthorizedBy  string `json:"authorized_by"`
	Timestamp     string `json:"timestamp"`
	Signature     string `json:"signature"`
}

func NewAWIDRegistryClient(httpClient *http.Client, dnsResolver TXTResolver) *RegistryClient {
	resolver := NewRegistryResolver(httpClient, dnsResolver)
	return &RegistryClient{
		DefaultRegistryURL: DefaultAWIDRegistryURL,
		Resolver:           resolver,
		HTTPClient:         resolver.HTTPClient,
	}
}

func (c *RegistryClient) SetFallbackRegistryURL(raw string) error {
	if c == nil {
		return fmt.Errorf("nil registry client")
	}
	if err := c.Resolver.SetFallbackRegistryURL(raw); err != nil {
		return err
	}
	canonical, err := canonicalRegistryServerOrigin(raw)
	if err != nil {
		return err
	}
	c.DefaultRegistryURL = canonical
	return nil
}

func (c *RegistryClient) DiscoverRegistry(ctx context.Context, domain string) (string, error) {
	return c.Resolver.DiscoverRegistry(ctx, domain)
}

func (c *RegistryClient) ResolveKey(ctx context.Context, didAW string) (*DidKeyResolution, error) {
	return c.ResolveKeyAt(ctx, c.defaultRegistryURL(), didAW)
}

func (c *RegistryClient) ResolveKeyAt(ctx context.Context, registryURL, didAW string) (*DidKeyResolution, error) {
	didAW = strings.TrimSpace(didAW)
	var wire didKeyResolutionWire
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, "/v1/did/"+urlPathEscape(didAW)+"/key", nil, nil, &wire); err != nil {
		return nil, err
	}
	res := &DidKeyResolution{
		DIDAW:         wire.DIDAW,
		CurrentDIDKey: wire.CurrentDIDKey,
	}
	if wire.LogHead != nil {
		res.LogHead = &DidKeyEvidence{
			Seq:            wire.LogHead.Seq,
			Operation:      wire.LogHead.Operation,
			PreviousDIDKey: wire.LogHead.PreviousDIDKey,
			NewDIDKey:      wire.LogHead.NewDIDKey,
			PrevEntryHash:  wire.LogHead.PrevEntryHash,
			EntryHash:      wire.LogHead.EntryHash,
			StateHash:      wire.LogHead.StateHash,
			AuthorizedBy:   wire.LogHead.AuthorizedBy,
			Signature:      wire.LogHead.Signature,
			Timestamp:      wire.LogHead.Timestamp,
		}
	}
	return res, nil
}

func (c *RegistryClient) GetDIDFull(ctx context.Context, registryURL, didAW string, signingKey ed25519.PrivateKey) (*DIDMapping, error) {
	path := "/v1/did/" + urlPathEscape(strings.TrimSpace(didAW)) + "/full"
	var out DIDMapping
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, signedPathHeaders(http.MethodGet, path, signingKey), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) GetDIDLog(ctx context.Context, registryURL, didAW string) ([]DidKeyEvidence, error) {
	path := "/v1/did/" + urlPathEscape(strings.TrimSpace(didAW)) + "/log"
	var out []DidKeyEvidence
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *RegistryClient) ListDIDAddressesAt(ctx context.Context, registryURL, didAW string) ([]RegistryAddress, error) {
	path := "/v1/did/" + urlPathEscape(strings.TrimSpace(didAW)) + "/addresses"
	var out RegistryAddressList
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Addresses, nil
}

func (c *RegistryClient) GetNamespace(ctx context.Context, domain string) (*RegistryNamespace, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.GetNamespaceAt(ctx, registryURL, domain)
}

func (c *RegistryClient) GetNamespaceAt(ctx context.Context, registryURL, domain string) (*RegistryNamespace, string, error) {
	var out RegistryNamespace
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, "/v1/namespaces/"+urlPathEscape(canonicalizeDomain(domain)), nil, nil, &out); err != nil {
		return nil, "", err
	}
	return &out, registryURL, nil
}

func (c *RegistryClient) ListNamespaceAddresses(ctx context.Context, domain string) ([]RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.ListNamespaceAddressesAt(ctx, registryURL, domain)
}

func (c *RegistryClient) ListNamespaceAddressesSigned(
	ctx context.Context,
	domain string,
	signingKey ed25519.PrivateKey,
) ([]RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.ListNamespaceAddressesAtSigned(ctx, registryURL, domain, signingKey)
}

func (c *RegistryClient) ListNamespaceAddressesAt(ctx context.Context, registryURL, domain string) ([]RegistryAddress, string, error) {
	var out RegistryAddressList
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, "/v1/namespaces/"+urlPathEscape(canonicalizeDomain(domain))+"/addresses", nil, nil, &out); err != nil {
		return nil, "", err
	}
	return out.Addresses, registryURL, nil
}

func (c *RegistryClient) ListNamespaceAddressesAtSigned(
	ctx context.Context,
	registryURL, domain string,
	signingKey ed25519.PrivateKey,
) ([]RegistryAddress, string, error) {
	return c.ListNamespaceAddressesAt(ctx, registryURL, domain)
}

func (c *RegistryClient) RegisterIdentity(
	ctx context.Context,
	registryURL string,
	did string,
	stableID string,
	signingKey ed25519.PrivateKey,
) (*DIDMapping, error) {
	registryURL = strings.TrimSpace(registryURL)
	did = strings.TrimSpace(did)
	stableID = strings.TrimSpace(stableID)

	if stableID == "" {
		return nil, fmt.Errorf("stableID is required")
	}
	if !strings.HasPrefix(stableID, "did:aw:") {
		return nil, fmt.Errorf("stableID must start with did:aw:")
	}
	if signingKey == nil {
		return nil, fmt.Errorf("signing key is required")
	}
	if pub := signingKey.Public().(ed25519.PublicKey); ComputeDIDKey(pub) != did {
		return nil, fmt.Errorf("did does not match signing key")
	}

	stateHash := stableIdentityStateHash(stableID, did)
	timestamp := registryNow().Format(time.RFC3339)
	proofPayload := CanonicalDidLogPayload(stableID, &DidKeyEvidence{
		Seq:            1,
		Operation:      "register_did",
		PreviousDIDKey: nil,
		NewDIDKey:      did,
		PrevEntryHash:  nil,
		StateHash:      stateHash,
		AuthorizedBy:   did,
		Timestamp:      timestamp,
	})
	payload := didRegisterRequest{
		AuthorizedBy:   did,
		DIDAW:          stableID,
		NewDIDKey:      did,
		Operation:      "register_did",
		PrevEntryHash:  nil,
		PreviousDIDKey: nil,
		Seq:            1,
		StateHash:      stateHash,
		Timestamp:      timestamp,
		Proof:          base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(proofPayload))),
	}
	if err := c.requestJSON(ctx, http.MethodPost, registryURL, "/v1/did", nil, payload, nil); err != nil {
		var regErr *RegistryError
		if !errors.As(err, &regErr) || regErr.StatusCode != http.StatusConflict {
			return nil, err
		}
		existing, resolveErr := c.ResolveKeyAt(ctx, registryURL, stableID)
		if resolveErr != nil {
			return nil, err
		}
		return nil, &AlreadyRegisteredError{
			DIDAW:          stableID,
			ExistingDIDKey: strings.TrimSpace(existing.CurrentDIDKey),
		}
	}
	return c.GetDIDFull(ctx, registryURL, stableID, signingKey)
}

func (c *RegistryClient) PublishEncryptionKey(
	ctx context.Context,
	registryURL string,
	didAW string,
	assertion *EncryptionKeyAssertion,
) error {
	didAW = strings.TrimSpace(didAW)
	if didAW == "" {
		return fmt.Errorf("did:aw is required")
	}
	if assertion == nil {
		return fmt.Errorf("encryption key assertion is required")
	}
	return c.requestJSON(ctx, http.MethodPost, registryURL, "/v1/did/"+urlPathEscape(didAW)+"/encryption-key", nil, assertion, nil)
}

func (c *RegistryClient) RotateDIDKey(
	ctx context.Context,
	registryURL string,
	didAW string,
	oldSigningKey ed25519.PrivateKey,
	newSigningKey ed25519.PrivateKey,
) (*DIDMapping, error) {
	if oldSigningKey == nil || newSigningKey == nil {
		return nil, fmt.Errorf("both old and new signing keys are required")
	}
	oldDID := ComputeDIDKey(oldSigningKey.Public().(ed25519.PublicKey))
	newDID := ComputeDIDKey(newSigningKey.Public().(ed25519.PublicKey))
	current, err := c.GetDIDFull(ctx, registryURL, didAW, oldSigningKey)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(current.CurrentDIDKey) != oldDID {
		return nil, fmt.Errorf("old signing key does not match the current did:key")
	}
	resolution, err := c.ResolveKeyAt(ctx, registryURL, didAW)
	if err != nil {
		return nil, err
	}
	if resolution.LogHead == nil {
		return nil, fmt.Errorf("DID registry response is missing log_head")
	}
	timestamp := registryNow().Format(time.RFC3339)
	prevEntryHash := strings.TrimSpace(resolution.LogHead.EntryHash)
	stateHash := stableIdentityStateHash(didAW, newDID)
	signaturePayload := CanonicalDidLogPayload(didAW, &DidKeyEvidence{
		Seq:            resolution.LogHead.Seq + 1,
		Operation:      "rotate_key",
		PreviousDIDKey: &oldDID,
		NewDIDKey:      newDID,
		PrevEntryHash:  &prevEntryHash,
		StateHash:      stateHash,
		AuthorizedBy:   oldDID,
		Timestamp:      timestamp,
	})
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(oldSigningKey, []byte(signaturePayload)))
	req := didUpdateRequest{
		Operation:     "rotate_key",
		NewDIDKey:     newDID,
		Seq:           resolution.LogHead.Seq + 1,
		PrevEntryHash: prevEntryHash,
		StateHash:     stateHash,
		AuthorizedBy:  oldDID,
		Timestamp:     timestamp,
		Signature:     signature,
	}
	if err := c.requestJSON(ctx, http.MethodPut, registryURL, "/v1/did/"+urlPathEscape(strings.TrimSpace(didAW)), nil, req, nil); err != nil {
		return nil, err
	}
	return c.GetDIDFull(ctx, registryURL, didAW, newSigningKey)
}

func (c *RegistryClient) requestJSON(ctx context.Context, method, registryURL, path string, headers map[string]string, body any, out any) error {
	for attempt := 0; ; attempt++ {
		req, err := c.newRequest(ctx, method, registryURL, path, headers, body)
		if err != nil {
			return err
		}
		resp, err := c.httpClient().Do(req)
		if err != nil {
			if shouldRetryRegistryTransportError(ctx, method, path, attempt, err) {
				if waitErr := waitForRegistryRetry(ctx, attempt); waitErr != nil {
					return waitErr
				}
				continue
			}
			return err
		}
		if shouldRetryRegistryResponse(ctx, method, path, attempt, resp) {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if waitErr := waitForRegistryRetry(ctx, attempt); waitErr != nil {
				return waitErr
			}
			continue
		}

		err = decodeRegistryResponse(resp, out)
		if err != nil && shouldRetryRegistryTransportError(ctx, method, path, attempt, err) {
			if waitErr := waitForRegistryRetry(ctx, attempt); waitErr != nil {
				return waitErr
			}
			continue
		}
		return err
	}
}

func decodeRegistryResponse(resp *http.Response, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseRegistryError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func shouldRetryRegistryTransportError(ctx context.Context, method, path string, attempt int, err error) bool {
	if attempt >= registryTransientMaxRetries || err == nil || ctx.Err() != nil || !isReplaySafeRegistryRequest(method, path) {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func shouldRetryRegistryResponse(ctx context.Context, method, path string, attempt int, resp *http.Response) bool {
	return resp != nil &&
		resp.StatusCode == http.StatusServiceUnavailable &&
		attempt < registryTransientMaxRetries &&
		ctx.Err() == nil &&
		isReplaySafeRegistryRequest(method, path)
}

func waitForRegistryRetry(ctx context.Context, attempt int) error {
	delay := registryTransientBackoffDelay(attempt)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func registryTransientBackoffDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := 100 * time.Millisecond
	for i := 0; i < attempt; i++ {
		delay *= 2
	}
	return delay
}

func isReplaySafeRegistryRequest(method, path string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return true
	}

	// Keep writes explicit: every current route below is either an idempotent
	// state set/upsert or is guarded by a deterministic identity, certificate,
	// address, team, delegation, or publication conflict check in AWID. Unknown
	// future writes must be audited before they inherit transport-level retries.
	segments := registryPathSegments(path)
	switch method {
	case http.MethodPut:
		return len(segments) == 3 && segments[0] == "v1" && segments[1] == "did"
	case http.MethodPatch:
		return len(segments) == 3 && segments[0] == "v1" && segments[1] == "namespaces"
	case http.MethodDelete:
		return isReplaySafeRegistryDeletePath(segments)
	case http.MethodPost:
		return isReplaySafeRegistryPostPath(segments)
	default:
		return false
	}
}

func registryPathSegments(path string) []string {
	path, _, _ = strings.Cut(strings.TrimSpace(path), "?")
	return strings.Split(strings.Trim(path, "/"), "/")
}

func isReplaySafeRegistryDeletePath(segments []string) bool {
	if len(segments) == 3 {
		return segments[0] == "v1" && segments[1] == "namespaces"
	}
	return len(segments) == 5 &&
		segments[0] == "v1" &&
		segments[1] == "namespaces" &&
		(segments[3] == "addresses" || segments[3] == "teams")
}

func isReplaySafeRegistryPostPath(segments []string) bool {
	if len(segments) == 2 {
		return segments[0] == "v1" && (segments[1] == "did" || segments[1] == "namespaces")
	}
	if len(segments) == 3 {
		return segments[0] == "v1" && segments[1] == "a2a" &&
			(segments[2] == "delegations" || segments[2] == "publications")
	}
	if len(segments) == 4 {
		return segments[0] == "v1" &&
			((segments[1] == "did" && segments[3] == "encryption-key") ||
				(segments[1] == "namespaces" &&
					(segments[3] == "reverify" || segments[3] == "addresses" || segments[3] == "teams")))
	}
	if len(segments) == 5 {
		return segments[0] == "v1" && segments[1] == "namespaces" &&
			segments[3] == "addresses" && segments[4] == "claims"
	}
	if len(segments) == 6 {
		return segments[0] == "v1" && segments[1] == "namespaces" && segments[3] == "teams" &&
			(segments[5] == "visibility" || segments[5] == "certificates")
	}
	return len(segments) == 7 &&
		segments[0] == "v1" && segments[1] == "namespaces" && segments[3] == "teams" &&
		segments[5] == "certificates" && segments[6] == "revoke"
}

func (c *RegistryClient) newRequest(ctx context.Context, method, registryURL, path string, headers map[string]string, body any) (*http.Request, error) {
	registryURL = strings.TrimSpace(registryURL)
	if registryURL == "" {
		registryURL = c.defaultRegistryURL()
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(registryURL, "/")+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if requestID := strings.TrimSpace(c.RequestID); requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req, nil
}

func (c *RegistryClient) defaultRegistryURL() string {
	if c == nil {
		return DefaultAWIDRegistryURL
	}
	if strings.TrimSpace(c.DefaultRegistryURL) != "" {
		return strings.TrimSpace(c.DefaultRegistryURL)
	}
	return DefaultAWIDRegistryURL
}

func (c *RegistryClient) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: APITimeout(), Transport: NewAPITransport()}
}

func signedPathHeaders(method, path string, signingKey ed25519.PrivateKey) map[string]string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	payload := timestamp + "\n" + method + "\n" + path
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(payload)))
	return map[string]string{
		"Authorization":    fmt.Sprintf("DIDKey %s %s", did, signature),
		"X-AWEB-Timestamp": timestamp,
	}
}

func parseRegistryError(resp *http.Response) error {
	body := readBodyString(resp)
	regErr := &RegistryError{
		StatusCode: resp.StatusCode,
		Detail:     body,
	}
	var parsed struct {
		Detail any `json:"detail"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err == nil {
		if detail, ok := parsed.Detail.(map[string]any); ok {
			if code, ok := detail["code"].(string); ok {
				regErr.Code = strings.TrimSpace(code)
			}
			if message, ok := detail["message"].(string); ok {
				regErr.Message = strings.TrimSpace(message)
			}
		}
	}
	return regErr
}

func (e *RegistryError) HasCode(code string) bool {
	if e == nil {
		return false
	}
	return strings.TrimSpace(e.Code) == strings.TrimSpace(code)
}
