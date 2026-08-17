package awid

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
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

// RecipientResolutionError means a signed message could not bind its direct
// recipient to a current did:key, so sending must stop before posting.
type RecipientResolutionError struct {
	Target      string
	MessageType string
	Err         error
}

func (e *RecipientResolutionError) Error() string {
	if e == nil {
		return ""
	}
	msgType := strings.TrimSpace(e.MessageType)
	if msgType == "" {
		msgType = "message"
	}
	if e.Err == nil {
		return fmt.Sprintf("resolve recipient %q for signed %s", e.Target, msgType)
	}
	return fmt.Sprintf("resolve recipient %q for signed %s: %v", e.Target, msgType, e.Err)
}

func (e *RecipientResolutionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func isRegistryAddressNotFound(err error) bool {
	if code, ok := HTTPStatusCode(err); ok && code == http.StatusNotFound {
		body, _ := HTTPErrorBody(err)
		return strings.Contains(body, "Address not found")
	}
	return false
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
	if strings.HasPrefix(strings.TrimSpace(env.ToDID), "did:aw:") && !strings.Contains(strings.TrimSpace(env.ToDID), ",") {
		env.ToStableID = strings.TrimSpace(env.ToDID)
		env.ToDID = ""
	}
	if strings.TrimSpace(env.ToStableID) == "" && strings.HasPrefix(strings.TrimSpace(env.To), "did:aw:") && !strings.Contains(strings.TrimSpace(env.To), ",") {
		env.ToStableID = strings.TrimSpace(env.To)
	}

	// Resolve recipient DID for recipient binding when we have a stable
	// identity target or an explicit routable address. Bare aliases are
	// team-scoped selectors; the server resolves them under the authenticated
	// team certificate.
	bindingTarget := ""
	if env.ToDID == "" {
		bindingTarget = strings.TrimSpace(env.ToStableID)
		if bindingTarget == "" && env.Type == "mail" && isRoutableAddressTarget(env.To) {
			bindingTarget = c.canonicalTrustAddress(env.To)
		} else if bindingTarget == "" && env.Type == "chat" && !strings.Contains(env.To, ",") && isRoutableAddressTarget(env.To) {
			bindingTarget = c.canonicalTrustAddress(env.To)
		}
	}
	globalStableTarget := strings.HasPrefix(strings.TrimSpace(env.ToStableID), "did:aw:")
	storedRouteGlobalTarget := globalStableTarget && env.AllowStoredRouteGlobalBinding
	bindingRequired := env.RequireRecipientBinding || (globalStableTarget && !env.AllowStoredRouteGlobalBinding)
	if c.resolver != nil && env.ToDID == "" && bindingTarget != "" && !storedRouteGlobalTarget {
		identity, err := c.resolver.Resolve(ctx, bindingTarget)
		if err != nil {
			if bindingRequired {
				return signedFields{}, &RecipientResolutionError{Target: bindingTarget, MessageType: env.Type, Err: err}
			}
			identity = nil
		}
		if identity != nil {
			if strings.TrimSpace(identity.DID) == "" {
				return signedFields{}, &RecipientResolutionError{Target: bindingTarget, MessageType: env.Type, Err: errors.New("missing current did:key")}
			}
			env.ToDID = strings.TrimSpace(identity.DID)
			if strings.TrimSpace(env.ToStableID) == "" && strings.TrimSpace(identity.StableID) != "" {
				env.ToStableID = strings.TrimSpace(identity.StableID)
			}
		}
	}
	if bindingRequired && env.ToDID == "" && bindingTarget != "" {
		return signedFields{}, &RecipientResolutionError{Target: bindingTarget, MessageType: env.Type, Err: errors.New("missing current did:key")}
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

func isRoutableAddressTarget(target string) bool {
	target = strings.TrimSpace(target)
	return strings.Contains(target, "/") || strings.Contains(target, "~")
}

const (
	// DefaultTimeout is the default HTTP timeout used by the client.
	// 30s leaves headroom for venue WiFi or mobile links where large request
	// bodies plus TLS setup and header wait can exceed shorter ceilings against
	// a healthy server. Override per-process with AWEB_HTTP_TIMEOUT.
	DefaultTimeout = 30 * time.Second

	MaxResponseSize = 10 * 1024 * 1024

	apiTransientMaxRetries = 3
)

var apiTransientRetryBaseDelay = 100 * time.Millisecond

// agentMeta holds cached metadata about a resolved agent.
type agentMeta struct {
	DID             string
	IdentityScope   string // "local" or "global"
	Custody         string // "self" or "custodial"
	Resolved        bool
	ResolutionError string // "not_found" or "unavailable" after a forced refresh
}

// Client is an aweb HTTP client.
//
// It is designed to be easy to extract into a standalone repo and to be used by:
// - the `aw` CLI
// - higher-level coordination products built on the same transport
type Client struct {
	baseURL                 string
	httpClient              *http.Client
	sseClient               *http.Client       // No response timeout; SSE connections are long-lived.
	signingKey              ed25519.PrivateKey // nil for legacy/custodial
	did                     string             // empty for legacy/custodial
	teamCertHeader          string             // base64-encoded team certificate for X-AWID-Team-Certificate
	teamID                  string             // team identifier from certificate, used in auth signature
	grantID                 string             // identity-grant id; non-empty selects grant auth with the session signing key
	certAlias               string             // certificate alias, used for signed payloads in cert-auth mode
	address                 string             // namespace/alias, used in signed envelopes
	e2eeSenderAddress       string             // explicit address for E2EE envelopes; empty for addressless local/team identities
	e2eeSenderAddressSet    bool
	stableID                string // did:aw:..., set on outgoing signed envelopes as from_stable_id
	e2eeEncryptionKey       *EncryptionKeyAssertion
	e2eePrivateKey          *ecdh.PrivateKey
	requireRecipientBinding bool
	resolver                IdentityResolver // optional; resolves recipient DID for to_did binding
	pinStore                *PinStore        // optional; TOFU pin store for sender identity verification
	pinStorePath            string           // disk path for persisting pin store
	pinStorePersistMu       sync.Mutex
	pinStoreBaseline        []byte
	pinStoreBaselineErr     error
	pinStorePersister       func(path string, expectedYAML, desiredYAML []byte) error
	pinMigrationObserver    func(PinMigrationDecline)
	metaCache               sync.Map     // address → *agentMeta; cached resolver results
	latestClientVersion     atomic.Value // last seen X-Latest-Client-Version header (string)
}

// New creates a new client.
func New(baseURL string) (*Client, error) {
	if _, err := url.Parse(baseURL); err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   APITimeout(),
			Transport: NewAPITransport(),
		},
		// No Timeout: SSE streams are long-lived. The transport still
		// bounds dial/TLS/header waits.
		sseClient: &http.Client{Transport: NewSSETransport()},
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

// NewWithGrant creates a client authenticated as an identity-grant session.
// The session key signs every request; the subject identity's root keys are
// never involved.
func NewWithGrant(baseURL string, sessionKey ed25519.PrivateKey, grantID string) (*Client, error) {
	if sessionKey == nil {
		return nil, fmt.Errorf("sessionKey must not be nil")
	}
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		return nil, fmt.Errorf("grantID must not be empty")
	}
	c, err := New(baseURL)
	if err != nil {
		return nil, err
	}
	c.signingKey = sessionKey
	c.did = ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey))
	c.grantID = grantID
	return c, nil
}

// GrantID returns the identity-grant id, or empty for non-grant clients.
func (c *Client) GrantID() string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.grantID)
}

func (c *Client) TeamID() string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.teamID)
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

// SSEClient returns the HTTP client used for SSE requests.
func (c *Client) SSEClient() *http.Client { return c.sseClient }

// SigningKey returns the client's signing key, or nil for legacy/custodial clients.
func (c *Client) SigningKey() ed25519.PrivateKey { return c.signingKey }

// DID returns the client's DID, or empty for legacy/custodial clients.
func (c *Client) DID() string { return c.did }

// Address returns the client's address, if configured.
func (c *Client) Address() string { return c.address }

// SetAddress sets the client's agent address (namespace/alias) for use in
// signed message envelopes.
func (c *Client) SetAddress(address string) { c.address = address }

// SetE2EESenderAddress sets the address to place in E2EE sender metadata.
// Use an explicit address from identity/certificate state, not a display
// fallback derived from domain + alias.
func (c *Client) SetE2EESenderAddress(address string) {
	c.e2eeSenderAddress = strings.TrimSpace(address)
	c.e2eeSenderAddressSet = true
}

func (c *Client) e2eeAddress() string {
	if c.e2eeSenderAddressSet {
		return strings.TrimSpace(c.e2eeSenderAddress)
	}
	return strings.TrimSpace(c.address)
}

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
	if identityTarget {
		if from == "" {
			return strings.TrimSpace(c.did)
		}
		return from
	}
	if preferAlias {
		if c.teamCertHeader != "" {
			if alias := c.certAlias; alias != "" {
				return alias
			}
		}
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
func (c *Client) SetStableID(id string) {
	c.stableID = id
	if strings.TrimSpace(id) != "" {
		c.requireRecipientBinding = true
	}
}

// StableID returns the client's stable identifier, if configured.
func (c *Client) StableID() string { return c.stableID }

// SetRequireRecipientBindingForDirectAddresses controls whether signed direct
// address sends must bind the recipient address to a current did:key before
// posting. Global identity clients should enable this so private or hidden
// registry addresses fail closed instead of falling through to local routing.
func (c *Client) SetRequireRecipientBindingForDirectAddresses(required bool) {
	c.requireRecipientBinding = required
}

// SetResolver sets the identity resolver used to resolve recipient DIDs
// for to_did binding in signed envelopes.
func (c *Client) SetResolver(r IdentityResolver) { c.resolver = r }

// Resolver returns the configured identity resolver, if any.
func (c *Client) Resolver() IdentityResolver { return c.resolver }

// HasTeamCertificateAuth reports whether this client can authenticate with a
// team certificate — the credential TeamRosterResolver requires for
// certificate-authenticated roster reads.
func (c *Client) HasTeamCertificateAuth() bool {
	return c != nil && strings.TrimSpace(c.teamCertHeader) != "" && len(c.signingKey) != 0
}

func (c *Client) SetE2EEKey(assertion *EncryptionKeyAssertion, privateKey *ecdh.PrivateKey) {
	if c == nil {
		return
	}
	c.e2eeEncryptionKey = assertion
	c.e2eePrivateKey = privateKey
}

func (c *Client) ResolveIdentity(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	if c == nil || c.resolver == nil {
		return nil, errors.New("aweb: no identity resolver configured")
	}
	return c.resolver.Resolve(ctx, identifier)
}

// PinMigrationOutcome names why an upgrade-on-first-sight migration was
// declined. The action is the same in every case — both pins are kept — but the
// operator situations differ: a same-identity decline is expected, a conflict is
// a different identity holding the stable id, and an unclassifiable one is
// repairable by recording the occupant's did:key.
type PinMigrationOutcome string

const (
	PinMigrationSameIdentity   PinMigrationOutcome = "same_identity"
	PinMigrationConflict       PinMigrationOutcome = "conflict"
	PinMigrationUnclassifiable PinMigrationOutcome = "unclassifiable"
)

// PinMigrationDecline reports a migration that did not happen.
type PinMigrationDecline struct {
	Outcome     PinMigrationOutcome
	StableID    string
	Address     string
	OccupantDID string
	IncomingDID string
}

// SetPinMigrationObserver registers a callback invoked when a stable-id
// migration is declined because the stable-id key already holds another pin.
func (c *Client) SetPinMigrationObserver(observe func(PinMigrationDecline)) {
	c.pinMigrationObserver = observe
}

// reportPinMigrationDecline classifies a declined migration by whether the
// occupant of the stable-id key can be shown to be the same identity. An
// occupant with no recorded did:key cannot be classified either way, and an
// absent field must never be read as proof of sameness.
func (c *Client) reportPinMigrationDecline(occupant *Pin, incomingDID, stableID, address string) {
	if c.pinMigrationObserver == nil {
		return
	}
	outcome := PinMigrationConflict
	switch {
	case strings.TrimSpace(occupant.DIDKey) == "":
		outcome = PinMigrationUnclassifiable
	case occupant.DIDKey == incomingDID:
		outcome = PinMigrationSameIdentity
	}
	c.pinMigrationObserver(PinMigrationDecline{
		Outcome:     outcome,
		StableID:    stableID,
		Address:     address,
		OccupantDID: occupant.DIDKey,
		IncomingDID: incomingDID,
	})
}

// SetPinStore sets the TOFU pin store for sender identity verification.
// If path is non-empty, the store is persisted to disk after updates.
func (c *Client) SetPinStore(ps *PinStore, path string) {
	c.pinStore = ps
	c.pinStorePath = path
	c.pinStoreBaseline = nil
	c.pinStoreBaselineErr = nil
	if ps != nil {
		c.pinStoreBaseline, c.pinStoreBaselineErr = ps.Encode()
	}
}

// SetPinStorePersister installs the cross-process compare-and-set writer used by
// aw. The callback must lock, reload, verify expectedYAML, and refuse a stale
// mutation before writing desiredYAML.
func (c *Client) SetPinStorePersister(persist func(path string, expectedYAML, desiredYAML []byte) error) {
	c.pinStorePersister = persist
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

func (c *Client) isCurrentTeamRosterReference(address string) bool {
	if _, _, ok := splitTeamMemberReference(address); ok {
		return true
	}
	chain, ok := c.resolver.(*ChainResolver)
	if !ok || chain.Team == nil {
		return false
	}
	_, _, ok = chain.Team.reference(address)
	return ok
}

// resolveAgentMeta returns cached identity-scope/custody metadata for a sender address.
// On first contact, resolves via the client's IdentityResolver and caches the result.
// Returns an unresolved marker if no resolver is set or resolution fails.
func (c *Client) resolveAgentMeta(ctx context.Context, address string) *agentMeta {
	return c.resolveAgentMetaFresh(ctx, address, false)
}

func (c *Client) resolveAgentMetaFresh(ctx context.Context, address string, forceRefresh bool) *agentMeta {
	rawAddress := strings.TrimSpace(address)
	trustAddress := c.canonicalTrustAddress(rawAddress)
	if trustAddress == "" {
		return &agentMeta{}
	}
	if !forceRefresh {
		if v, ok := c.metaCache.Load(trustAddress); ok {
			return v.(*agentMeta)
		}
	}
	fallback := &agentMeta{
		IdentityScope: IdentityModeGlobal,
		Custody:       CustodySelf,
		Resolved:      true,
	}
	if c.resolver != nil {
		resolve := c.resolver.Resolve
		if forceRefresh {
			fresh, ok := c.resolver.(FreshIdentityResolver)
			if !ok {
				return &agentMeta{ResolutionError: "unavailable"}
			}
			resolve = fresh.ResolveFresh
		}
		if identity, err := resolve(ctx, trustAddress); err == nil {
			meta := &agentMeta{
				DID:           strings.TrimSpace(identity.DID),
				IdentityScope: IdentityModeGlobal,
				Custody:       CustodySelf,
				Resolved:      true,
			}
			if identity.IdentityScope != "" {
				meta.IdentityScope = NormalizeIdentityScope(identity.IdentityScope)
			}
			if identity.Custody != "" {
				meta.Custody = identity.Custody
			}
			c.metaCache.Store(trustAddress, meta)
			return meta
		} else if forceRefresh {
			resolutionError := "unavailable"
			if code, ok := HTTPStatusCode(err); ok && code == http.StatusNotFound {
				resolutionError = "not_found"
			}
			return &agentMeta{ResolutionError: resolutionError}
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
// signature verification. It suppresses contact tags for local senders and
// then applies continuity pinning using shared resolver metadata.
func (c *Client) NormalizeSenderTrust(ctx context.Context, status VerificationStatus, rawAddress, fromDID, fromStableID string, ra *RotationAnnouncement, repl *ReplacementAnnouncement, isContact *bool) (VerificationStatus, *bool) {
	// Mail applies recipient binding before sender continuity normalization.
	// Never let local-sender cache reconciliation weaken that authoritative
	// recipient mismatch to verification_stale.
	recipientBindingMismatch := status == IdentityMismatch
	if strings.TrimSpace(rawAddress) == "" {
		return status, isContact
	}
	trustAddress := c.canonicalTrustAddress(rawAddress)
	localTeamReference := c.isCurrentTeamRosterReference(trustAddress)
	if status != Verified && status != VerifiedLegacy && status != VerifiedCustodial &&
		localTeamReference && strings.TrimSpace(fromStableID) == "" {
		return status, isContact
	}
	var meta *agentMeta
	acceptedSignature := status == Verified || status == VerifiedLegacy || status == VerifiedCustodial
	if acceptedSignature && !recipientBindingMismatch && localTeamReference && strings.TrimSpace(fromDID) != "" {
		fresh := c.resolveAgentMetaFresh(ctx, rawAddress, true)
		if fresh == nil || !fresh.Resolved {
			if fresh != nil && fresh.ResolutionError == "not_found" {
				return IdentityMismatch, nil
			}
			return VerificationStale, nil
		}
		if fresh.IdentityScope == IdentityModeLocal {
			return c.verifyResolvedLocalSender(fresh, strings.TrimSpace(rawAddress), trustAddress, fromDID, status), nil
		}
		if strings.TrimSpace(fromStableID) == "" {
			return IdentityMismatch, nil
		}
		meta = fresh
	}
	if meta == nil {
		meta = c.resolveAgentMeta(ctx, rawAddress)
	}
	if strings.TrimSpace(fromStableID) == "" || (meta.Resolved && meta.IdentityScope == IdentityModeLocal) {
		isContact = nil
	}
	var registryConfirmedCurrentKey bool
	var verifiedHead *VerifiedLogHead
	status, registryConfirmedCurrentKey, verifiedHead = c.checkStableIdentityRegistry(ctx, status, trustAddress, fromDID, fromStableID)
	status = c.checkTOFUPinWithMeta(ctx, status, strings.TrimSpace(rawAddress), trustAddress, fromDID, fromStableID, ra, repl, meta, registryConfirmedCurrentKey)
	// Persist after the pin exists: on first contact the pin is created by the
	// check above, so recording the checkpoint earlier would be dropped.
	// An advanced anti-rollback checkpoint that is not durable would let the next
	// process accept a log head we have already moved past (default-aajc.8), so a
	// failure to commit it must not be reported as verified.
	if err := c.persistVerifiedHeadCheckpoint(fromStableID, verifiedHead); err != nil {
		if c.pinStore != nil {
			c.pinStore.undurable.Store(true)
		}
		if status == Verified || status == VerifiedCustodial {
			status = VerificationStale
		}
	}
	if status == IdentityMismatch && !recipientBindingMismatch && localTeamReference && strings.TrimSpace(fromDID) != "" && !strings.HasPrefix(strings.TrimSpace(fromStableID), "did:aw:") {
		status = c.verifyLocalSenderAgainstCurrentRoster(ctx, strings.TrimSpace(rawAddress), trustAddress, fromDID)
	}
	return status, isContact
}

func (c *Client) verifyLocalSenderAgainstCurrentRoster(ctx context.Context, rawAddress, trustAddress, fromDID string) VerificationStatus {
	fresh := c.resolveAgentMetaFresh(ctx, rawAddress, true)
	if fresh == nil || !fresh.Resolved {
		if fresh != nil && fresh.ResolutionError == "not_found" {
			return IdentityMismatch
		}
		return VerificationStale
	}
	if fresh.IdentityScope != IdentityModeLocal {
		return IdentityMismatch
	}
	return c.verifyResolvedLocalSender(fresh, rawAddress, trustAddress, fromDID, Verified)
}

func (c *Client) verifyResolvedLocalSender(fresh *agentMeta, rawAddress, trustAddress, fromDID string, acceptedStatus VerificationStatus) VerificationStatus {
	if strings.TrimSpace(fresh.DID) == "" {
		return VerificationStale
	}
	if strings.TrimSpace(fresh.DID) != strings.TrimSpace(fromDID) {
		return IdentityMismatch
	}
	if c.pinStore != nil {
		c.pinStore.mu.Lock()
		removed := c.pinStore.RemoveAddress(trustAddress)
		if rawAddress != "" && rawAddress != trustAddress {
			removed = c.pinStore.RemoveAddress(rawAddress) || removed
		}
		c.pinStore.mu.Unlock()
		if removed {
			// A removal that does not persist leaves the old pin on disk, so the
			// next process is stricter, not laxer. Not a continuity claim.
			_ = c.savePinStore()
		}
	}
	return acceptedStatus
}

// NormalizeRecipientBinding applies the local recipient-binding check after
// signature verification and any sender-side trust normalization.
func (c *Client) NormalizeRecipientBinding(status VerificationStatus, toDID string, toStableID string) VerificationStatus {
	return c.checkRecipientBinding(status, toDID, toStableID)
}

func (c *Client) checkStableIdentityRegistry(ctx context.Context, status VerificationStatus, trustAddress, fromDID, fromStableID string) (VerificationStatus, bool, *VerifiedLogHead) {
	if status != Verified || strings.TrimSpace(fromStableID) == "" || strings.TrimSpace(fromDID) == "" {
		return status, false, nil
	}
	if !strings.HasPrefix(strings.TrimSpace(fromStableID), "did:aw:") {
		return status, false, nil
	}
	verifier, ok := c.resolver.(StableIdentityVerifier)
	if !ok {
		return status, false, nil
	}
	// Restore the anti-rollback anchor from the checkpoint persisted with the
	// pin. The resolver's in-memory head cache is what refuses a sequence
	// regression or a split view, but it is forgotten on restart — so without
	// this a registry can serve a valid truncated prefix and roll a rotated
	// identity back to a retired key (default-aajc.8).
	c.seedVerifiedHeadFromPin(fromStableID)
	var result *StableIdentityVerification
	if currentVerifier, ok := c.resolver.(CurrentStableIdentityVerifier); ok {
		result = currentVerifier.VerifyStableIdentityCurrent(ctx, trustAddress, fromStableID, fromDID)
	} else {
		result = verifier.VerifyStableIdentity(ctx, trustAddress, fromStableID)
	}
	if result == nil {
		return status, false, nil
	}
	switch result.Outcome {
	case StableIdentityStaleCache:
		return VerificationStale, false, nil
	case StableIdentityVerified:
		currentDIDKey := strings.TrimSpace(result.CurrentDIDKey)
		if currentDIDKey != "" && currentDIDKey != fromDID {
			return IdentityMismatch, false, nil
		}
		return status, currentDIDKey == fromDID, result.VerifiedHead
	case StableIdentityHardError:
		return IdentityMismatch, false, nil
	}
	return status, false, nil
}

// CheckTOFUPin checks a verified message against the TOFU pin store.
// On first contact, creates a pin. On subsequent contact with matching DID,
// updates last_seen. On DID mismatch, checks for a valid rotation announcement
// before returning IdentityMismatch.
// Returns the status unchanged if no pin store is set, the message is not
// verified, or from_did/from_address is empty.
// Uses the resolver to determine the sender's identity scope (local identities
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
	if meta.IdentityScope == IdentityModeLocal {
		c.pinStore.mu.Lock()
		removed := c.pinStore.RemoveAddress(trustAddress)
		rawAddress = strings.TrimSpace(rawAddress)
		if rawAddress != "" && rawAddress != trustAddress {
			removed = c.pinStore.RemoveAddress(rawAddress) || removed
		}
		c.pinStore.mu.Unlock()
		if removed {
			// As above: an unpersisted removal fails safe (the pin survives).
			_ = c.savePinStore()
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
				// A stable id is one key and a pin carries one address, so an
				// identity already pinned at another address cannot also move
				// onto that key here. Migrating anyway would overwrite the pin
				// holding the other address and produce a store ParsePinStore
				// refuses, so keep both pins and stay on the did:key for this
				// address. The occupant decides only what gets reported.
				if occupant, occupied := c.pinStore.Pins[fromStableID]; occupied && occupant != existingPin {
					pinKey = fromDID
					c.reportPinMigrationDecline(occupant, fromDID, fromStableID, trustAddress)
				} else {
					delete(c.pinStore.Pins, fromDID)
					existingPin.StableID = fromStableID
					c.pinStore.Pins[fromStableID] = existingPin
					c.pinStore.Addresses[trustAddress] = fromStableID
				}
			}
		}
	}

	pinResult := c.pinStore.CheckPin(trustAddress, pinKey, meta.IdentityScope)
	switch pinResult {
	case PinNew:
		c.pinStore.StorePin(pinKey, trustAddress, "", "")
		if fromStableID != "" {
			c.pinStore.Pins[pinKey].StableID = fromStableID
			c.pinStore.Pins[pinKey].DIDKey = fromDID
		}
		status = c.commitContinuity(status)
	case PinOK:
		if fromStableID != "" {
			if pin, ok := c.pinStore.Pins[pinKey]; ok && strings.TrimSpace(pin.DIDKey) != "" && pin.DIDKey != fromDID {
				// Same stable identity, different did:key: this is key rotation,
				// which the DID log DOES prove (did:aw -> did:key), so a verified
				// registry chain is sufficient here. It says nothing about address
				// ownership — that is enforced in the mismatch branch below.
				if registryConfirmedCurrentKey {
					c.pinStore.StorePin(pinKey, trustAddress, "", "")
					c.pinStore.Pins[pinKey].StableID = fromStableID
					c.pinStore.Pins[pinKey].DIDKey = fromDID
					return c.commitContinuity(status)
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
		status = c.commitRefresh(status)
	case PinMismatch:
		pinnedKey := c.pinStore.Addresses[trustAddress]
		// A verified DID log proves did:aw -> did:key. It proves NOTHING about
		// which address that identity may claim, so it is not authority to take
		// over an address pinned to a different stable identity: an attacker who
		// legitimately owns did:aw:attacker can have a wholly valid log. Only the
		// address authority can authorize the transfer, via a replacement
		// announcement signed by the namespace controller named in the address's
		// _awid DNS TXT record. Absent that proof the pin stands and the mismatch
		// is reported (default-aajc.8).
		if fromStableID != "" && pinnedKey == fromStableID {
			if pin, ok := c.pinStore.Pins[pinnedKey]; ok {
				if strings.TrimSpace(pin.DIDKey) != "" && pin.DIDKey == fromDID {
					c.pinStore.StorePin(pinnedKey, trustAddress, "", "")
					c.pinStore.Pins[pinnedKey].StableID = fromStableID
					return c.commitContinuity(status)
				}
				if strings.TrimSpace(pin.DIDKey) != "" &&
					((ra != nil && c.verifyRotationAnnouncement(ra, fromDID, pin.DIDKey)) ||
						(repl != nil && c.verifyReplacementAnnouncement(ctx, trustAddress, repl, fromDID, pin.DIDKey))) {
					c.pinStore.StorePin(pinnedKey, trustAddress, "", "")
					c.pinStore.Pins[pinnedKey].StableID = fromStableID
					c.pinStore.Pins[pinnedKey].DIDKey = fromDID
					return c.commitContinuity(status)
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
			return c.commitContinuity(status)
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

// savePinStore commits the trust database. Atomic write via temp+rename.
// Callers that established or rotated a continuity record MUST NOT report the
// message verified when this fails — see commitContinuity.
func (c *Client) savePinStore() error {
	if c.pinStorePath == "" {
		return nil
	}
	if c.pinStorePersister == nil {
		return c.pinStore.Save(c.pinStorePath)
	}

	c.pinStorePersistMu.Lock()
	defer c.pinStorePersistMu.Unlock()
	if c.pinStoreBaselineErr != nil {
		return fmt.Errorf("encode pin-store precondition: %w", c.pinStoreBaselineErr)
	}
	desired, err := c.pinStore.Encode()
	if err != nil {
		return fmt.Errorf("encode desired pin store: %w", err)
	}
	if err := c.pinStorePersister(c.pinStorePath, c.pinStoreBaseline, desired); err != nil {
		return err
	}
	c.pinStoreBaseline = append(c.pinStoreBaseline[:0], desired...)
	return nil
}

// commitContinuity persists a newly established or rotated pin and downgrades
// the status when it cannot be made durable. A pin that never reaches disk is
// not continuity: the next process sees no pin, treats the sender as first
// contact, and trusts whoever answers to that address. Reporting "verified" for
// a record we failed to keep would be a claim we cannot honour (default-aajc.9).
//
// This applies to records that are new or changed. A save that only loses a
// last_seen refresh leaves the durable pin intact and is deliberately not
// downgraded, so a full disk cannot make every already-pinned sender unverifiable.
func (c *Client) commitContinuity(status VerificationStatus) VerificationStatus {
	if err := c.savePinStore(); err != nil {
		c.pinStore.undurable.Store(true)
		return VerificationStale
	}
	c.pinStore.undurable.Store(false)
	return status
}

// commitRefresh persists a change that is NOT itself a continuity claim — a
// last_seen touch on a pin that already matched. Normally a failure here is an
// availability problem and the status stands, because the durable pin is
// unchanged.
//
// It stops standing once a continuity commit has already failed. The mutated pin
// is still in memory, so the next message from that sender takes this path and
// would be reported verified against a record that is not on disk at all. While
// the store is undurable we retry and keep the sender unverified until it lands.
func (c *Client) commitRefresh(status VerificationStatus) VerificationStatus {
	if !c.pinStore.undurable.Load() {
		_ = c.savePinStore()
		return status
	}
	if err := c.savePinStore(); err != nil {
		return VerificationStale
	}
	c.pinStore.undurable.Store(false)
	return status
}

// checkRecipientBinding downgrades a Verified status to IdentityMismatch
// if the message's recipient binding doesn't match the client's identity.
// A matching stable binding is sufficient across local key rotation; otherwise
// we fall back to the current did:key binding.
func (c *Client) checkRecipientBinding(status VerificationStatus, toDID string, toStableID string) VerificationStatus {
	if status != Verified && status != VerifiedLegacy && status != VerifiedCustodial {
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
	if strings.HasPrefix(strings.TrimSpace(toDID), "did:aw:") {
		if strings.TrimSpace(toStableID) != "" {
			return status
		}
		stableID := strings.TrimSpace(c.stableID)
		if stableID != "" {
			if strings.EqualFold(strings.TrimSpace(toDID), stableID) {
				return status
			}
			return IdentityMismatch
		}
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
	RequestID  string
}

func (e *APIError) Error() string {
	requestID := strings.TrimSpace(e.RequestID)
	suffix := ""
	if requestID != "" {
		suffix = fmt.Sprintf(" (x-request-id: %s)", requestID)
	}
	if e.Body == "" {
		return fmt.Sprintf("aweb: http %d%s", e.StatusCode, suffix)
	}
	if e.StatusCode == http.StatusServiceUnavailable && isTransientServiceUnavailableBody(e.Body) {
		return fmt.Sprintf("aweb: service temporarily unavailable (http %d%s): %s", e.StatusCode, suffix, e.Body)
	}
	return fmt.Sprintf("aweb: http %d%s: %s", e.StatusCode, suffix, e.Body)
}

// HTTPStatusCode returns the HTTP status code for API errors.
func HTTPStatusCode(err error) (int, bool) {
	var e *APIError
	if errors.As(err, &e) {
		return e.StatusCode, true
	}
	var registryErr *RegistryError
	if errors.As(err, &registryErr) {
		return registryErr.StatusCode, true
	}
	return 0, false
}

// HTTPErrorBody returns the response body for API errors.
func HTTPErrorBody(err error) (string, bool) {
	var e *APIError
	if errors.As(err, &e) {
		return e.Body, true
	}
	var registryErr *RegistryError
	if errors.As(err, &registryErr) {
		return registryErr.Detail, true
	}
	return "", false
}

// Get performs an HTTP GET request and decodes the JSON response.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

// Post performs an HTTP POST request with a JSON body and decodes the JSON response.
func (c *Client) Post(ctx context.Context, path string, in any, out any) error {
	return c.Do(ctx, http.MethodPost, path, in, out)
}

// PostWithHeaders performs an HTTP POST with additional request headers.
func (c *Client) PostWithHeaders(ctx context.Context, path string, in any, out any, extraHeaders map[string]string) error {
	return c.DoWithHeaders(ctx, http.MethodPost, path, in, out, extraHeaders)
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
	return c.DoWithHeaders(ctx, method, path, in, out, nil)
}

// DoWithHeaders performs an HTTP request with optional JSON body, response
// decoding, and additional request headers.
func (c *Client) DoWithHeaders(ctx context.Context, method, path string, in any, out any, extraHeaders map[string]string) error {
	resp, err := c.DoRawWithHeaders(ctx, method, path, "application/json", in, extraHeaders)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: ReadErrorExcerpt(resp.Body), RequestID: resp.Header.Get("X-Request-ID")}
	}
	data, err := ReadAllBounded(resp.Body, MaxResponseSize)
	if err != nil {
		return err
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
	return c.DoRawWithHeaders(ctx, method, path, accept, in, nil)
}

// DoRawWithHeaders performs an HTTP request and returns the raw response.
func (c *Client) DoRawWithHeaders(ctx context.Context, method, path, accept string, in any, extraHeaders map[string]string) (*http.Response, error) {
	var bodyBytes []byte
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		bodyBytes = data
	}

	if strings.HasSuffix(c.baseURL, "/api") && strings.HasPrefix(path, "/api/") {
		path = strings.TrimPrefix(path, "/api")
	}
	buildRequest := func() (*http.Request, error) {
		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
		if err != nil {
			return nil, err
		}
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", accept)
		for key, value := range extraHeaders {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key != "" && value != "" {
				req.Header.Set(key, value)
			}
		}
		if c.grantID != "" && c.signingKey != nil {
			// Grant auth: session did:key signature over the identity-grant
			// envelope. aud, method, path, and body_sha256 bind the request to
			// the grant, mirroring the v2 team envelope canonicalization.
			timestamp := time.Now().UTC().Format(time.RFC3339)
			credential, err := SignIdentityGrantCredential(c.signingKey, method, req.URL, c.grantID, bodyBytes, timestamp)
			if err != nil {
				return nil, err
			}
			for key := range credential.Headers {
				req.Header.Set(key, credential.Headers.Get(key))
			}
		} else if c.teamCertHeader != "" && c.signingKey != nil {
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
		return req, nil
	}

	for attempt := 0; ; attempt++ {
		req, err := buildRequest()
		if err != nil {
			return nil, err
		}
		TraceHTTPRequest(req, bodyBytes)
		resp, err := DoNoRedirectWithTimeout(c.httpClient, req, APITimeout())
		if err != nil {
			decorated := decorateTimeoutError(method, err)
			if shouldRetryAPITransportError(ctx, method, path, bodyBytes, attempt, err) {
				if sleepErr := reportAndSleepAPIRetry(ctx, attempt, method, path); sleepErr != nil {
					return nil, sleepErr
				}
				continue
			}
			return nil, decorated
		}
		if err := TraceHTTPResponse(resp); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		if v := resp.Header.Get("X-Latest-Client-Version"); v != "" {
			c.latestClientVersion.Store(v)
		}
		if retry, err := shouldRetryAPIResponse(ctx, method, path, bodyBytes, attempt, resp); err != nil {
			_ = resp.Body.Close()
			return nil, err
		} else if retry {
			_ = resp.Body.Close()
			if sleepErr := reportAndSleepAPIRetry(ctx, attempt, method, path); sleepErr != nil {
				return nil, sleepErr
			}
			continue
		}
		return resp, nil
	}
}

func shouldRetryAPITransportError(ctx context.Context, method, path string, body []byte, attempt int, err error) bool {
	if attempt >= apiTransientMaxRetries || err == nil || ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return isSafeHTTPMethod(method) || isIdempotentSendRequest(method, path, body)
}

func shouldRetryAPIResponse(ctx context.Context, method, path string, body []byte, attempt int, resp *http.Response) (bool, error) {
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable || attempt >= apiTransientMaxRetries || ctx.Err() != nil {
		return false, nil
	}
	if isSafeHTTPMethod(method) || isIdempotentSendRequest(method, path, body) {
		return true, nil
	}
	return false, nil
}

func reportAndSleepAPIRetry(ctx context.Context, attempt int, method, path string) error {
	retry := attempt + 1
	fmt.Fprintf(os.Stderr, "service temporarily unavailable, retrying %d/%d (%s %s)\n", retry, apiTransientMaxRetries, strings.ToUpper(strings.TrimSpace(method)), path)
	delay := apiTransientBackoffDelay(attempt)
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

func apiTransientBackoffDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := apiTransientRetryBaseDelay
	for i := 0; i < attempt; i++ {
		delay *= 2
	}
	return delay
}

func isSafeHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func isIdempotentSendRequest(method, path string, body []byte) bool {
	if strings.ToUpper(strings.TrimSpace(method)) != http.MethodPost || !requestBodyHasMessageID(body) {
		return false
	}
	path = strings.TrimSpace(path)
	if path == "/v1/messages" || path == "/v1/chat/sessions" {
		return true
	}
	return strings.HasPrefix(path, "/v1/chat/sessions/") && strings.HasSuffix(path, "/messages")
}

func requestBodyHasMessageID(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	messageID, _ := raw["message_id"].(string)
	return strings.TrimSpace(messageID) != ""
}

func isTransientServiceUnavailableBody(body string) bool {
	body = strings.ToLower(strings.TrimSpace(body))
	return strings.Contains(body, "awid registry unavailable") || strings.Contains(body, "temporarily unavailable")
}

func traceEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AW_TRACE"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// TraceHTTPRequest writes redacted request detail when AW_TRACE is enabled.
func TraceHTTPRequest(req *http.Request, body []byte) {
	if !traceEnabled() || req == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "AW TRACE request: %s %s\n", req.Method, req.URL.String())
	traceHeaders("AW TRACE request header", req.Header, true)
	fmt.Fprintf(os.Stderr, "AW TRACE request body: %s\n", string(body))
}

// TraceHTTPResponse writes redacted response detail when AW_TRACE is enabled.
func TraceHTTPResponse(resp *http.Response) error {
	if !traceEnabled() || resp == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "AW TRACE response: HTTP %d\n", resp.StatusCode)
	traceHeaders("AW TRACE response header", resp.Header, true)
	if resp.Body == nil {
		fmt.Fprintln(os.Stderr, "AW TRACE response body:")
		return nil
	}
	originalBody := resp.Body
	data, err := ReadAllBounded(originalBody, MaxResponseSize)
	if err != nil {
		return err
	}
	if err := originalBody.Close(); err != nil {
		resp.Body = http.NoBody
		return fmt.Errorf("close traced HTTP response body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	fmt.Fprintf(os.Stderr, "AW TRACE response body: %s\n", string(data))
	return nil
}

func traceHeaders(prefix string, headers http.Header, redact bool) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := headers.Values(key)
		if redact && shouldRedactTraceHeader(key) {
			values = []string{"<redacted>"}
		}
		for _, value := range values {
			fmt.Fprintf(os.Stderr, "%s: %s: %s\n", prefix, key, value)
		}
	}
}

func shouldRedactTraceHeader(key string) bool {
	switch http.CanonicalHeaderKey(strings.TrimSpace(key)) {
	case "Authorization", "Cookie", "Set-Cookie", "X-Aweb-Signed-Payload", "X-Awid-Team-Certificate", "X-Aweb-Grant-Id", "X-AWEB-Signed-Payload", "X-AWID-Team-Certificate", "X-AWEB-Grant-ID":
		return true
	default:
		return false
	}
}

// decorateTimeoutError marks timed-out mutating requests as ambiguous: the
// request may have reached the server and applied before the response was
// lost, so blind retries risk duplicate writes. Reads stay undecorated —
// retrying a timed-out read is always safe.
func decorateTimeoutError(method string, err error) error {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return err
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		return err
	}
	return fmt.Errorf("%w\nRequest timed out before a response was received; it may have applied. Check current state before retrying.", err)
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

// verifiedHeadSeeder is implemented by resolvers that keep an anti-rollback
// anchor, so the client can restore it from the persisted pin checkpoint.
type verifiedHeadSeeder interface {
	SeedVerifiedHead(stableID string, head *VerifiedLogHead)
}

func (c *Client) seedVerifiedHeadFromPin(stableID string) {
	seeder, ok := c.resolver.(verifiedHeadSeeder)
	if !ok || c.pinStore == nil {
		return
	}
	c.pinStore.mu.Lock()
	pin, hasPin := c.pinStore.Pins[stableID]
	var seq int
	var entryHash, didKey string
	if hasPin && pin != nil {
		seq, entryHash, didKey = pin.LogSeq, pin.LogEntryHash, pin.DIDKey
	}
	c.pinStore.mu.Unlock()
	if seq < 1 || entryHash == "" {
		return
	}
	seeder.SeedVerifiedHead(stableID, &VerifiedLogHead{
		Seq:           seq,
		EntryHash:     entryHash,
		CurrentDIDKey: didKey,
	})
}

// persistVerifiedHeadCheckpoint records the verified head with the pin so the
// anchor survives a restart. It only ever advances: a lower sequence is ignored,
// so a stale response cannot weaken the checkpoint.
func (c *Client) persistVerifiedHeadCheckpoint(stableID string, head *VerifiedLogHead) error {
	if c.pinStore == nil {
		return nil
	}
	if head == nil || head.Seq < 1 || strings.TrimSpace(head.EntryHash) == "" {
		return nil
	}
	c.pinStore.mu.Lock()
	pin, ok := c.pinStore.Pins[stableID]
	changed := false
	if ok && pin != nil && head.Seq > pin.LogSeq {
		pin.LogSeq = head.Seq
		pin.LogEntryHash = head.EntryHash
		changed = true
	}
	c.pinStore.mu.Unlock()
	if changed {
		return c.savePinStore()
	}
	return nil
}
