package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// signedFields holds the identity fields attached to outgoing messages
// when the client has a signing key.
type signedFields struct {
	FromDID       string
	ToDID         string
	ToStableID    string
	FromStableID  string
	Signature     string
	SigningKeyID  string
	Timestamp     string
	MessageID     string
	SignedPayload string
}

// signEnvelope signs a MessageEnvelope and returns the fields to embed
// in the request. When the client has no signing key (legacy/custodial),
// returns a zero signedFields. Callers stamp the returned fields onto
// the request struct before posting.
func (c *Client) signEnvelope(ctx context.Context, env *MessageEnvelope) (signedFields, error) {
	if c.signingKey == nil {
		return signedFields{}, nil
	}
	if strings.TrimSpace(env.From) == "" {
		env.From = c.address
	}
	env.FromDID = c.did
	env.FromStableID = c.stableID
	env.Timestamp = time.Now().UTC().Format(time.RFC3339)
	msgID, err := GenerateUUID4()
	if err != nil {
		return signedFields{}, err
	}
	env.MessageID = msgID

	// Stable did:aw targets belong in to_stable_id; to_did is reserved for the
	// recipient's current did:key binding.
	if strings.HasPrefix(strings.TrimSpace(env.ToDID), "did:aw:") {
		env.ToStableID = strings.TrimSpace(env.ToDID)
		env.ToDID = ""
	}
	if strings.TrimSpace(env.ToStableID) == "" && strings.HasPrefix(strings.TrimSpace(env.To), "did:aw:") {
		env.ToStableID = strings.TrimSpace(env.To)
	}

	// Resolve recipient DID for recipient binding when we have a stable
	// identity target, or for mail when we only have a routable address.
	if c.resolver != nil && env.ToDID == "" {
		target := strings.TrimSpace(env.ToStableID)
		if target == "" && env.Type == "mail" {
			target = c.canonicalTrustAddress(env.To)
		} else if target == "" && env.Type == "chat" && !strings.Contains(env.To, ",") {
			target = c.canonicalTrustAddress(env.To)
		}
		if target != "" {
			if identity, err := c.resolver.Resolve(ctx, target); err == nil && identity.DID != "" {
				env.ToDID = identity.DID
				if strings.TrimSpace(env.ToStableID) == "" && strings.TrimSpace(identity.StableID) != "" {
					env.ToStableID = strings.TrimSpace(identity.StableID)
				}
			}
		}
	}

	sig, err := SignMessage(c.signingKey, env)
	if err != nil {
		return signedFields{}, fmt.Errorf("sign message: %w", err)
	}
	return signedFields{
		FromDID:       c.did,
		ToDID:         env.ToDID,
		ToStableID:    env.ToStableID,
		FromStableID:  c.stableID,
		Signature:     sig,
		SigningKeyID:  c.did,
		Timestamp:     env.Timestamp,
		MessageID:     env.MessageID,
		SignedPayload: CanonicalJSON(env),
	}, nil
}

const (
	// DefaultTimeout is the default HTTP timeout used by the client.
	DefaultTimeout = 10 * time.Second

	MaxResponseSize = 10 * 1024 * 1024
)

// agentMeta holds cached metadata about a resolved agent.
type agentMeta struct {
	Lifetime string // "persistent" or "ephemeral"
	Custody  string // "self" or "custodial"
	Resolved bool
}

// Client is an aweb HTTP client.
//
// It is designed to be easy to extract into a standalone repo and to be used by:
// - the `aw` CLI
// - higher-level coordination products built on the same transport
type Client struct {
	baseURL             string
	httpClient          *http.Client
	sseClient           *http.Client       // No response timeout; SSE connections are long-lived.
	signingKey          ed25519.PrivateKey // nil for legacy/custodial
	did                 string             // empty for legacy/custodial
	teamCertHeader      string             // base64-encoded team certificate for X-AWID-Team-Certificate
	teamID              string             // team identifier from certificate, used in auth signature
	certAlias           string             // certificate alias, used for signed payloads in cert-auth mode
	address             string             // namespace/alias, used in signed envelopes
	stableID            string             // did:aw:..., set on outgoing signed envelopes as from_stable_id
	resolver            IdentityResolver   // optional; resolves recipient DID for to_did binding
	pinStore            *PinStore          // optional; TOFU pin store for sender identity verification
	pinStorePath        string             // disk path for persisting pin store
	metaCache           sync.Map           // address → *agentMeta; cached resolver results
	latestClientVersion atomic.Value       // last seen X-Latest-Client-Version header (string)
}

// New creates a new client.
func New(baseURL string) (*Client, error) {
	if _, err := url.Parse(baseURL); err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		sseClient: &http.Client{},
	}, nil
}

// NewWithIdentity creates an authenticated client with signing capability.
func NewWithIdentity(baseURL string, signingKey ed25519.PrivateKey, did string) (*Client, error) {
	if signingKey == nil {
		return nil, fmt.Errorf("signingKey must not be nil")
	}
	if did == "" {
		return nil, fmt.Errorf("did must not be empty")
	}
	expected := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if did != expected {
		return nil, fmt.Errorf("did does not match signingKey")
	}
	c, err := New(baseURL)
	if err != nil {
		return nil, err
	}
	c.signingKey = signingKey
	c.did = did
	return c, nil
}

// NewWithCertificate creates an authenticated client that uses DIDKey signatures
// and a team certificate instead of API key authentication.
func NewWithCertificate(baseURL string, signingKey ed25519.PrivateKey, cert *TeamCertificate) (*Client, error) {
	if signingKey == nil {
		return nil, fmt.Errorf("signingKey must not be nil")
	}
	if cert == nil {
		return nil, fmt.Errorf("certificate must not be nil")
	}
	did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if did != cert.MemberDIDKey {
		return nil, fmt.Errorf("signing key did:key %s does not match certificate member_did_key %s", did, cert.MemberDIDKey)
	}
	certHeader, err := EncodeTeamCertificateHeader(cert)
	if err != nil {
		return nil, fmt.Errorf("encode team certificate: %w", err)
	}
	c, err := New(baseURL)
	if err != nil {
		return nil, err
	}
	c.signingKey = signingKey
	c.did = did
	c.teamCertHeader = certHeader
	c.teamID = cert.Team
	c.certAlias = strings.TrimSpace(cert.Alias)
	return c, nil
}

// SetHTTPClient replaces the client's HTTP client used for normal API calls.
// A nil client is ignored.
func (c *Client) SetHTTPClient(httpClient *http.Client) {
	if httpClient == nil {
		return
	}
	c.httpClient = httpClient
}

// SetSSEClient replaces the client's HTTP client used for SSE requests.
// A nil client is ignored.
func (c *Client) SetSSEClient(httpClient *http.Client) {
	if httpClient == nil {
		return
	}
	c.sseClient = httpClient
}

// HTTPClient returns the HTTP client used for standard JSON API calls.
func (c *Client) HTTPClient() *http.Client { return c.httpClient }

// SigningKey returns the client's signing key, or nil for legacy/custodial clients.
func (c *Client) SigningKey() ed25519.PrivateKey { return c.signingKey }

// DID returns the client's DID, or empty for legacy/custodial clients.
func (c *Client) DID() string { return c.did }

// Address returns the client's address, if configured.
func (c *Client) Address() string { return c.address }

// SetAddress sets the client's agent address (namespace/alias) for use in
// signed message envelopes.
func (c *Client) SetAddress(address string) { c.address = address }

func (c *Client) addressAlias() string {
	parts := strings.SplitN(c.address, "/", 2)
	if len(parts) == 2 && parts[1] != "" {
		return parts[1]
	}
	return ""
}

func (c *Client) signedPayloadFrom(identityTarget, preferAlias bool) string {
	from := strings.TrimSpace(c.address)
	if c.signingKey == nil {
		return from
	}
	if c.teamCertHeader != "" {
		if alias := c.certAlias; alias != "" {
			return alias
		}
	}
	if identityTarget {
		if from == "" {
			return strings.TrimSpace(c.did)
		}
		return from
	}
	if preferAlias {
		if alias := c.addressAlias(); alias != "" {
			return alias
		}
	}
	if from == "" {
		return strings.TrimSpace(c.did)
	}
	return from
}

// SetStableID sets the client's stable identifier (did:aw:...) for use
// as from_stable_id in outgoing signed envelopes.
func (c *Client) SetStableID(id string) { c.stableID = id }

// StableID returns the client's stable identifier, if configured.
func (c *Client) StableID() string { return c.stableID }

// SetResolver sets the identity resolver used to resolve recipient DIDs
// for to_did binding in signed envelopes.
func (c *Client) SetResolver(r IdentityResolver) { c.resolver = r }

func (c *Client) ResolveIdentity(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	if c == nil || c.resolver == nil {
		return nil, errors.New("aweb: no identity resolver configured")
	}
	return c.resolver.Resolve(ctx, identifier)
}

// SetPinStore sets the TOFU pin store for sender identity verification.
// If path is non-empty, the store is persisted to disk after updates.
func (c *Client) SetPinStore(ps *PinStore, path string) {
	c.pinStore = ps
	c.pinStorePath = path
}

// LatestClientVersion returns the most recent X-Latest-Client-Version header
// value seen in any API response, or empty if no header was received.
func (c *Client) LatestClientVersion() string {
	if v, ok := c.latestClientVersion.Load().(string); ok {
		return v
	}
	return ""
}

func (c *Client) canonicalTrustAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	if strings.Contains(address, "/") || strings.Contains(address, "~") {
		return address
	}
	if namespace := c.namespaceSlug(); namespace != "" {
		return namespace + "/" + address
	}
	return address
}

// resolveAgentMeta returns cached lifetime/custody metadata for a sender address.
// On first contact, resolves via the client's IdentityResolver and caches the result.
// Returns an unresolved marker if no resolver is set or resolution fails.
func (c *Client) resolveAgentMeta(ctx context.Context, address string) *agentMeta {
	rawAddress := strings.TrimSpace(address)
	trustAddress := c.canonicalTrustAddress(rawAddress)
	if trustAddress == "" {
		return &agentMeta{}
	}
	if v, ok := c.metaCache.Load(trustAddress); ok {
		return v.(*agentMeta)
	}
	fallback := &agentMeta{
		Lifetime: LifetimePersistent,
		Custody:  CustodySelf,
		Resolved: true,
	}
	if c.resolver != nil {
		if identity, err := c.resolver.Resolve(ctx, trustAddress); err == nil {
			meta := &agentMeta{
				Lifetime: LifetimePersistent,
				Custody:  CustodySelf,
				Resolved: true,
			}
			if identity.Lifetime != "" {
				meta.Lifetime = identity.Lifetime
			}
			if identity.Custody != "" {
				meta.Custody = identity.Custody
			}
			c.metaCache.Store(trustAddress, meta)
			return meta
		}
	}
	// Bare local aliases are ambiguous across teams; fail closed unless the
	// resolver resolved them under the current namespace. Fully qualified
	// addresses keep the historical fallback behavior.
	if rawAddress != trustAddress {
		return &agentMeta{}
	}
	// Resolver absent or failed for an already-qualified address: return
	// defaults but don't cache, so a transient failure retries on the next
	// message.
	return fallback
}

// NormalizeSenderTrust applies sender-specific trust normalization after
// signature verification. It suppresses contact tags for ephemeral senders and
// then applies continuity pinning using shared resolver metadata.
func (c *Client) NormalizeSenderTrust(ctx context.Context, status VerificationStatus, rawAddress, fromDID, fromStableID string, ra *RotationAnnouncement, repl *ReplacementAnnouncement, isContact *bool) (VerificationStatus, *bool) {
	if strings.TrimSpace(rawAddress) == "" {
		return status, isContact
	}
	trustAddress := c.canonicalTrustAddress(rawAddress)
	meta := c.resolveAgentMeta(ctx, rawAddress)
	if strings.TrimSpace(fromStableID) == "" || (meta.Resolved && meta.Lifetime == LifetimeEphemeral) {
		isContact = nil
	}
	var registryConfirmedCurrentKey bool
	status, registryConfirmedCurrentKey = c.checkStableIdentityRegistry(ctx, status, trustAddress, fromDID, fromStableID)
	status = c.checkTOFUPinWithMeta(ctx, status, strings.TrimSpace(rawAddress), trustAddress, fromDID, fromStableID, ra, repl, meta, registryConfirmedCurrentKey)
	return status, isContact
}

// NormalizeRecipientBinding applies the local recipient-binding check after
// signature verification and any sender-side trust normalization.
func (c *Client) NormalizeRecipientBinding(status VerificationStatus, toDID string, toStableID string) VerificationStatus {
	return c.checkRecipientBinding(status, toDID, toStableID)
}

func (c *Client) checkStableIdentityRegistry(ctx context.Context, status VerificationStatus, trustAddress, fromDID, fromStableID string) (VerificationStatus, bool) {
	if status != Verified || strings.TrimSpace(fromStableID) == "" || strings.TrimSpace(fromDID) == "" {
		return status, false
	}
	if !strings.HasPrefix(strings.TrimSpace(fromStableID), "did:aw:") {
		return status, false
	}
	verifier, ok := c.resolver.(StableIdentityVerifier)
	if !ok {
		return status, false
	}
	result := verifier.VerifyStableIdentity(ctx, trustAddress, fromStableID)
	if result == nil {
		return status, false
	}
	switch result.Outcome {
	case StableIdentityVerified:
		currentDIDKey := strings.TrimSpace(result.CurrentDIDKey)
		if currentDIDKey != "" && currentDIDKey != fromDID {
			return IdentityMismatch, false
		}
		return status, currentDIDKey == fromDID
	case StableIdentityHardError:
		return IdentityMismatch, false
	}
	return status, false
}

// CheckTOFUPin checks a verified message against the TOFU pin store.
// On first contact, creates a pin. On subsequent contact with matching DID,
// updates last_seen. On DID mismatch, checks for a valid rotation announcement
// before returning IdentityMismatch.
// Returns the status unchanged if no pin store is set, the message is not
// verified, or from_did/from_address is empty.
// Uses the resolver to determine the sender's lifetime (ephemeral agents
// skip pinning) and custody (custodial agents return VerifiedCustodial).
//
// When fromStableID is present, pins are keyed by stable_id instead of did:key.
// The pin stores the last observed did:key for that stable identity, so a
// stable_id can survive key rotation while still enforcing continuity.
func (c *Client) CheckTOFUPin(ctx context.Context, status VerificationStatus, fromAddress, fromDID, fromStableID string, ra *RotationAnnouncement, repl *ReplacementAnnouncement) VerificationStatus {
	if c.pinStore == nil || (status != Verified && status != VerifiedCustodial) || fromDID == "" || fromAddress == "" {
		return status
	}

	// Validate stable_id prefix before using it as a pin key.
	if fromStableID != "" && !strings.HasPrefix(fromStableID, "did:aw:") {
		fromStableID = "" // Treat invalid prefix as absent.
	}

	trustAddress := c.canonicalTrustAddress(fromAddress)
	meta := c.resolveAgentMeta(ctx, trustAddress)
	return c.checkTOFUPinWithMeta(ctx, status, strings.TrimSpace(fromAddress), trustAddress, fromDID, fromStableID, ra, repl, meta, false)
}

func (c *Client) checkTOFUPinWithMeta(ctx context.Context, status VerificationStatus, rawAddress, trustAddress, fromDID, fromStableID string, ra *RotationAnnouncement, repl *ReplacementAnnouncement, meta *agentMeta, registryConfirmedCurrentKey bool) VerificationStatus {
	if c.pinStore == nil || (status != Verified && status != VerifiedCustodial) || fromDID == "" || trustAddress == "" || meta == nil {
		return status
	}
	if !meta.Resolved {
		return status
	}
	if meta.Lifetime == LifetimeEphemeral {
		c.pinStore.mu.Lock()
		removed := c.pinStore.RemoveAddress(trustAddress)
		rawAddress = strings.TrimSpace(rawAddress)
		if rawAddress != "" && rawAddress != trustAddress {
			removed = c.pinStore.RemoveAddress(rawAddress) || removed
		}
		c.pinStore.mu.Unlock()
		if removed {
			c.savePinStore()
		}
		return status
	}

	if meta.Custody == CustodyCustodial && status == Verified {
		status = VerifiedCustodial
	}

	c.pinStore.mu.Lock()
	defer c.pinStore.mu.Unlock()

	pinKey := fromDID
	if fromStableID != "" {
		pinKey = fromStableID

		// Upgrade-on-first-sight: if we have a did:key pin for this address
		// and the did:key matches, migrate to stable_id pin before the check.
		if existingDID, ok := c.pinStore.Addresses[trustAddress]; ok && existingDID == fromDID {
			if existingPin, hasDIDPin := c.pinStore.Pins[fromDID]; hasDIDPin {
				delete(c.pinStore.Pins, fromDID)
				existingPin.StableID = fromStableID
				c.pinStore.Pins[fromStableID] = existingPin
				c.pinStore.Addresses[trustAddress] = fromStableID
			}
		}
	}

	pinResult := c.pinStore.CheckPin(trustAddress, pinKey, meta.Lifetime)
	switch pinResult {
	case PinNew:
		c.pinStore.StorePin(pinKey, trustAddress, "", "")
		if fromStableID != "" {
			c.pinStore.Pins[pinKey].StableID = fromStableID
			c.pinStore.Pins[pinKey].DIDKey = fromDID
		}
		c.savePinStore()
	case PinOK:
		if fromStableID != "" {
			if pin, ok := c.pinStore.Pins[pinKey]; ok && strings.TrimSpace(pin.DIDKey) != "" && pin.DIDKey != fromDID {
				// A verified registry chain is authoritative for persistent
				// identities; stale local TOFU must not block archive/recreate.
				// Security assumption: awid enforces a did:aw belongs to one
				// current address; the client does not independently prove that.
				if registryConfirmedCurrentKey {
					c.pinStore.StorePin(pinKey, trustAddress, "", "")
					c.pinStore.Pins[pinKey].StableID = fromStableID
					c.pinStore.Pins[pinKey].DIDKey = fromDID
					c.savePinStore()
					return status
				}
				if (ra == nil || !c.verifyRotationAnnouncement(ra, fromDID, pin.DIDKey)) &&
					(repl == nil || !c.verifyReplacementAnnouncement(ctx, trustAddress, repl, fromDID, pin.DIDKey)) {
					return IdentityMismatch
				}
			}
		}
		c.pinStore.StorePin(pinKey, trustAddress, "", "")
		if fromStableID != "" {
			c.pinStore.Pins[pinKey].StableID = fromStableID
			c.pinStore.Pins[pinKey].DIDKey = fromDID
		}
		c.savePinStore()
	case PinMismatch:
		pinnedKey := c.pinStore.Addresses[trustAddress]
		// A verified registry chain proves the address now belongs to this
		// stable identity and did:key, so replace the stale address pin.
		// Security assumption: awid enforces a did:aw belongs to one current
		// address; the client does not independently prove that.
		if registryConfirmedCurrentKey && fromStableID != "" {
			c.pinStore.RemoveAddress(trustAddress)
			c.pinStore.StorePin(pinKey, trustAddress, "", "")
			c.pinStore.Pins[pinKey].StableID = fromStableID
			c.pinStore.Pins[pinKey].DIDKey = fromDID
			c.savePinStore()
			return status
		}
		if fromStableID != "" && pinnedKey == fromStableID {
			if pin, ok := c.pinStore.Pins[pinnedKey]; ok {
				if strings.TrimSpace(pin.DIDKey) != "" && pin.DIDKey == fromDID {
					c.pinStore.StorePin(pinnedKey, trustAddress, "", "")
					c.pinStore.Pins[pinnedKey].StableID = fromStableID
					c.savePinStore()
					return status
				}
				if strings.TrimSpace(pin.DIDKey) != "" &&
					((ra != nil && c.verifyRotationAnnouncement(ra, fromDID, pin.DIDKey)) ||
						(repl != nil && c.verifyReplacementAnnouncement(ctx, trustAddress, repl, fromDID, pin.DIDKey))) {
					c.pinStore.StorePin(pinnedKey, trustAddress, "", "")
					c.pinStore.Pins[pinnedKey].StableID = fromStableID
					c.pinStore.Pins[pinnedKey].DIDKey = fromDID
					c.savePinStore()
					return status
				}
			}
		}
		if (ra != nil && c.verifyRotationAnnouncement(ra, fromDID, pinnedKey)) ||
			(repl != nil && c.verifyReplacementAnnouncement(ctx, trustAddress, repl, fromDID, pinnedKey)) {
			delete(c.pinStore.Pins, pinnedKey)
			c.pinStore.StorePin(pinKey, trustAddress, "", "")
			if fromStableID != "" {
				c.pinStore.Pins[pinKey].StableID = fromStableID
				c.pinStore.Pins[pinKey].DIDKey = fromDID
			}
			c.savePinStore()
			return status
		}
		return IdentityMismatch
	}
	return status
}

// verifyRotationAnnouncement checks that a rotation announcement is valid:
// the old key signed the transition from old_did to new_did, the message's
// from_did matches the announcement's new_did, and the announcement's old_did
// matches the currently pinned DID.
func (c *Client) verifyRotationAnnouncement(ra *RotationAnnouncement, messageDID, pinnedDID string) bool {
	if ra.OldDID == "" || ra.NewDID == "" || ra.OldKeySignature == "" || ra.Timestamp == "" {
		return false
	}
	if !isTimestampFresh(ra.Timestamp) {
		return false
	}
	if ra.NewDID != messageDID {
		return false
	}
	if ra.OldDID != pinnedDID {
		return false
	}
	oldPub, err := ExtractPublicKey(ra.OldDID)
	if err != nil {
		return false
	}
	ok, err := VerifyRotationSignature(oldPub, ra.OldDID, ra.NewDID, ra.Timestamp, ra.OldKeySignature)
	return err == nil && ok
}

func (c *Client) verifyReplacementAnnouncement(ctx context.Context, address string, repl *ReplacementAnnouncement, messageDID, pinnedDID string) bool {
	if repl == nil {
		return false
	}
	if repl.Address == "" || repl.OldDID == "" || repl.NewDID == "" || repl.ControllerDID == "" || repl.Timestamp == "" || repl.ControllerSignature == "" {
		return false
	}
	if !isTimestampFresh(repl.Timestamp) {
		return false
	}
	if repl.Address != address || repl.NewDID != messageDID || repl.OldDID != pinnedDID {
		return false
	}
	if c.resolver == nil {
		return false
	}
	identity, err := c.resolver.Resolve(ctx, address)
	if err != nil {
		return false
	}
	if identity.ControllerDID == "" || identity.ControllerDID != repl.ControllerDID {
		return false
	}
	controllerPub, err := ExtractPublicKey(repl.ControllerDID)
	if err != nil {
		return false
	}
	ok, err := VerifyReplacementSignature(controllerPub, repl.Address, repl.ControllerDID, repl.OldDID, repl.NewDID, repl.Timestamp, repl.ControllerSignature)
	return err == nil && ok
}

func (c *Client) savePinStore() {
	if c.pinStorePath != "" {
		// Best effort: atomic write via temp+rename. A failed save means
		// the next process loads a stale store and may re-pin.
		_ = c.pinStore.Save(c.pinStorePath)
	}
}

// checkRecipientBinding downgrades a Verified status to IdentityMismatch
// if the message's recipient binding doesn't match the client's identity.
// A matching stable binding is sufficient across local key rotation; otherwise
// we fall back to the current did:key binding.
func (c *Client) checkRecipientBinding(status VerificationStatus, toDID string, toStableID string) VerificationStatus {
	if status != Verified {
		return status
	}
	if stableID := strings.TrimSpace(c.stableID); stableID != "" && strings.TrimSpace(toStableID) != "" {
		if strings.EqualFold(strings.TrimSpace(toStableID), stableID) {
			return status
		}
		return IdentityMismatch
	}
	if toDID == "" || c.did == "" {
		return status
	}
	if toDID != c.did {
		return IdentityMismatch
	}
	return status
}

// APIError represents an HTTP error from the aweb API.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("aweb: http %d", e.StatusCode)
	}
	return fmt.Sprintf("aweb: http %d: %s", e.StatusCode, e.Body)
}

// HTTPStatusCode returns the HTTP status code for API errors.
func HTTPStatusCode(err error) (int, bool) {
	var e *APIError
	if !errors.As(err, &e) {
		return 0, false
	}
	return e.StatusCode, true
}

// HTTPErrorBody returns the response body for API errors.
func HTTPErrorBody(err error) (string, bool) {
	var e *APIError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Body, true
}

// Get performs an HTTP GET request and decodes the JSON response.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

// Post performs an HTTP POST request with a JSON body and decodes the JSON response.
func (c *Client) Post(ctx context.Context, path string, in any, out any) error {
	return c.Do(ctx, http.MethodPost, path, in, out)
}

// Patch performs an HTTP PATCH request with a JSON body and decodes the JSON response.
func (c *Client) Patch(ctx context.Context, path string, in any, out any) error {
	return c.Do(ctx, http.MethodPatch, path, in, out)
}

// Put performs an HTTP PUT request with a JSON body and decodes the JSON response.
func (c *Client) Put(ctx context.Context, path string, in any, out any) error {
	return c.Do(ctx, http.MethodPut, path, in, out)
}

// Delete performs an HTTP DELETE request.
func (c *Client) Delete(ctx context.Context, path string) error {
	return c.Do(ctx, http.MethodDelete, path, nil, nil)
}

// Do performs an HTTP request with optional JSON body and response decoding.
func (c *Client) Do(ctx context.Context, method, path string, in any, out any) error {
	resp, err := c.DoRaw(ctx, method, path, "application/json", in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, MaxResponseSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}
	return nil
}

// DoRaw performs an HTTP request and returns the raw response.
func (c *Client) DoRaw(ctx context.Context, method, path, accept string, in any) (*http.Response, error) {
	var body io.Reader
	var bodyBytes []byte
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		bodyBytes = data
		body = bytes.NewReader(data)
	}

	if strings.HasSuffix(c.baseURL, "/api") && strings.HasPrefix(path, "/api/") {
		path = strings.TrimPrefix(path, "/api")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", accept)
	if c.teamCertHeader != "" && c.signingKey != nil {
		// Certificate auth: DIDKey signature over {body_sha256, team_id, timestamp}.
		// body_sha256 binds the request body to the signature without the
		// server having to consume the body stream for signature verification.
		timestamp := time.Now().UTC().Format(time.RFC3339)
		signPayload := certAuthSignPayload(c.teamID, timestamp, bodyBytes)
		sig := ed25519.Sign(c.signingKey, signPayload)
		req.Header.Set("Authorization", fmt.Sprintf("DIDKey %s %s", c.did, base64.RawStdEncoding.EncodeToString(sig)))
		req.Header.Set("X-AWEB-Timestamp", timestamp)
		req.Header.Set("X-AWID-Team-Certificate", c.teamCertHeader)
	} else if c.signingKey != nil {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		signPayload := identityAuthSignPayload(c.stableID, timestamp, bodyBytes)
		sig := ed25519.Sign(c.signingKey, signPayload)
		req.Header.Set("Authorization", fmt.Sprintf("DIDKey %s %s", c.did, base64.RawStdEncoding.EncodeToString(sig)))
		req.Header.Set("X-AWEB-Timestamp", timestamp)
		if c.stableID != "" {
			req.Header.Set("X-AWEB-DID-AW", c.stableID)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if v := resp.Header.Get("X-Latest-Client-Version"); v != "" {
		c.latestClientVersion.Store(v)
	}
	return resp, nil
}

// certAuthSignPayload builds the canonical JSON bytes for certificate auth:
// {"body_sha256":"<hex>","team_id":"<team_id>","timestamp":"<ts>"} —
// sorted keys, no whitespace. body_sha256 is the hex SHA256 of the request
// body bytes (empty body hashes the empty string).
func certAuthSignPayload(teamID, timestamp string, body []byte) []byte {
	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])
	payload, err := CanonicalJSONValue(map[string]string{
		"body_sha256": bodyHash,
		"team_id":     teamID,
		"timestamp":   timestamp,
	})
	if err != nil {
		panic(fmt.Sprintf("certAuthSignPayload: %v", err))
	}
	return []byte(payload)
}

func identityAuthSignPayload(didAW, timestamp string, body []byte) []byte {
	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])
	payload, err := CanonicalJSONValue(map[string]string{
		"body_sha256": bodyHash,
		"did_aw":      didAW,
		"timestamp":   timestamp,
	})
	if err != nil {
		panic(fmt.Sprintf("identityAuthSignPayload: %v", err))
	}
	return []byte(payload)
}
