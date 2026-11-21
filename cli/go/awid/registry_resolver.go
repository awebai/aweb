package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	registryDiscoveryTTL = 15 * time.Minute
	registryAddressTTL   = 5 * time.Minute
	registryKeyTTL       = 15 * time.Minute
	// registryForcedReadInterval bounds the reads a disagreeing cached answer
	// forces: one per sender per interval (docs/trust-model.md).
	registryForcedReadInterval = 30 * time.Second
)

type cachedValue[T any] struct {
	value     T
	expiresAt time.Time
}

type registryAddressResponse struct {
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

type registryTeamMemberResponse struct {
	TeamID        string `json:"team_id"`
	CertificateID string `json:"certificate_id"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw"`
	MemberAddress string `json:"member_address"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope"`
	IssuedAt      string `json:"issued_at"`
}

type didKeyEvidenceWire struct {
	Seq            int     `json:"seq"`
	Operation      string  `json:"operation"`
	PreviousDIDKey *string `json:"previous_did_key"`
	NewDIDKey      string  `json:"new_did_key"`
	PrevEntryHash  *string `json:"prev_entry_hash"`
	EntryHash      string  `json:"entry_hash"`
	StateHash      string  `json:"state_hash"`
	AuthorizedBy   string  `json:"authorized_by"`
	Signature      string  `json:"signature"`
	Timestamp      string  `json:"timestamp"`
}

type didKeyResolutionWire struct {
	IDTree        json.RawMessage         `json:"id_tree"`
	DIDAW         string                  `json:"did_aw"`
	CurrentDIDKey string                  `json:"current_did_key"`
	LogHead       *didKeyEvidenceWire     `json:"log_head"`
	EncryptionKey *EncryptionKeyAssertion `json:"encryption_key,omitempty"`
}

func (w *didKeyResolutionWire) idTreeEnrollment() IDTreeEnrollmentResult {
	keyResponse := map[string]any{}
	if w.IDTree != nil {
		var tree any
		if json.Unmarshal(w.IDTree, &tree) != nil {
			tree = nil
		}
		keyResponse["id_tree"] = tree
	}
	return KeyResponseIDTree(keyResponse)
}

type registryAddressCacheValue struct {
	authority DomainAuthority
	response  *registryAddressResponse
}

type registryTeamMemberCacheValue struct {
	authority DomainAuthority
	response  *registryTeamMemberResponse
}

type RegistryResolver struct {
	// trust holds the registry origins the operator named on the current
	// command line or in the program's own configuration;
	// pinnedHTTPClient reaches every origin that is neither those, the
	// built-in default nor AWID_REGISTRY_URL. Tests in this package set pinnedHTTPClient.
	trust            registryTrust
	pinnedMu         sync.Mutex
	pinnedHTTPClient *http.Client

	// TeamReadSigningKey optionally authenticates team-member reads as a member
	// or controller. Configure before first use; caches belong to this caller.
	TeamReadSigningKey  ed25519.PrivateKey
	HTTPClient          *http.Client
	DNSResolver         TXTResolver
	Now                 func() time.Time
	fallbackRegistryURL string
	identityDomain      string
	mu                  sync.Mutex
	registryCache       map[string]cachedValue[DomainAuthority]
	addressCache        map[string]cachedValue[*registryAddressCacheValue]
	memberCache         map[string]cachedValue[*registryTeamMemberCacheValue]
	keyCache            map[string]cachedValue[*DidKeyResolution]
	headCache           map[string]*VerifiedLogHead
	receivedRegistries  map[string]*RegistryResolver
	forcedReads         map[string]forcedRegistryRead
}

// forcedRegistryRead is the last read a disagreeing cached answer forced for
// one sender's address or key.
type forcedRegistryRead struct {
	at     time.Time
	failed bool
}

func NewRegistryResolver(httpClient *http.Client, dnsResolver TXTResolver) *RegistryResolver {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: APITimeout(), Transport: NewAPITransport()}
	}
	if dnsResolver == nil {
		dnsResolver = &NetTXTResolver{}
	}
	return &RegistryResolver{
		HTTPClient:    httpClient,
		DNSResolver:   dnsResolver,
		Now:           time.Now,
		registryCache: make(map[string]cachedValue[DomainAuthority]),
		addressCache:  make(map[string]cachedValue[*registryAddressCacheValue]),
		memberCache:   make(map[string]cachedValue[*registryTeamMemberCacheValue]),
		keyCache:      make(map[string]cachedValue[*DidKeyResolution]),
		headCache:     make(map[string]*VerifiedLogHead),
		forcedReads:   make(map[string]forcedRegistryRead),
	}
}

// claimForcedRead decides whether a cached answer that disagrees with a
// signed message may be read again from the registry now: once per
// registryForcedReadInterval for that sender. When it may not, lastFailed
// reports whether the read that used the interval failed; the cache then still
// holds the older answer.
func (r *RegistryResolver) claimForcedRead(key string) (allowed bool, lastFailed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.forcedReads == nil {
		r.forcedReads = make(map[string]forcedRegistryRead)
	}
	now := r.now()
	if last, ok := r.forcedReads[key]; ok && now.Sub(last.at) < registryForcedReadInterval {
		return false, last.failed
	}
	r.forcedReads[key] = forcedRegistryRead{at: now}
	return true, false
}

// recordForcedRead records how a claimed forced read ended.
func (r *RegistryResolver) recordForcedRead(key string, failed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if read, ok := r.forcedReads[key]; ok {
		read.failed = failed
		r.forcedReads[key] = read
	}
}

func (r *RegistryResolver) SetFallbackRegistryURL(raw string) error {
	canonical, err := canonicalFallbackRegistryURL(raw)
	if err != nil {
		return err
	}
	r.setRegistryPolicy(canonical, "")
	return nil
}

// SetIdentityRegistryURL configures the registry pinned for the identity's own
// domain while allowing address resolution to discover foreign registries.
func (r *RegistryResolver) SetIdentityRegistryURL(raw, ownDomain string) error {
	canonical, err := canonicalFallbackRegistryURL(raw)
	if err != nil {
		return err
	}
	if canonical == "" {
		r.setRegistryPolicy("", "")
		return nil
	}
	ownDomain = canonicalizeDomain(ownDomain)
	if ownDomain == "" {
		return fmt.Errorf("identity domain is required with an identity registry URL")
	}
	r.setRegistryPolicy(canonical, ownDomain)
	return nil
}

func (r *RegistryResolver) setRegistryPolicy(fallbackRegistryURL, identityDomain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fallbackRegistryURL == fallbackRegistryURL && r.identityDomain == identityDomain {
		return
	}
	r.fallbackRegistryURL = fallbackRegistryURL
	r.identityDomain = identityDomain
	clear(r.registryCache)
	clear(r.addressCache)
	clear(r.memberCache)
	clear(r.keyCache)
}

func canonicalFallbackRegistryURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	return CanonicalRegistryServerOrigin(raw)
}

func (r *RegistryResolver) Resolve(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	return r.resolve(ctx, identifier, false)
}

func (r *RegistryResolver) ResolveFresh(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	return r.resolve(ctx, identifier, true)
}

func (r *RegistryResolver) resolve(ctx context.Context, identifier string, forceRefresh bool) (*ResolvedIdentity, error) {
	if strings.HasPrefix(strings.TrimSpace(identifier), "did:aw:") {
		return nil, fmt.Errorf("RegistryResolver: bare did:aw first-contact is unsupported; use domain/name address or stored route")
	}

	if teamID, alias, ok := splitTeamMemberReference(identifier); ok {
		member, err := r.resolveTeamMemberFresh(ctx, teamID, alias, forceRefresh)
		if err != nil {
			return nil, err
		}
		address := strings.TrimSpace(member.response.MemberAddress)
		if address == "" {
			address = strings.TrimSpace(identifier)
		}
		if stableID := strings.TrimSpace(member.response.MemberDIDAW); stableID != "" {
			keyRes, err := r.resolveKeyFresh(ctx, member.authority.RegistryURL, stableID, forceRefresh)
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(keyRes.DIDAW) != stableID {
				return nil, fmt.Errorf("RegistryResolver: key did:aw mismatch for %s", identifier)
			}
			pub, err := ExtractPublicKey(keyRes.CurrentDIDKey)
			if err != nil {
				return nil, fmt.Errorf("RegistryResolver: invalid current did:key: %w", err)
			}
			deliveryOrigin := ""
			if domain, name, ok := splitRegistryAddress(address); ok {
				addr, err := r.resolveAddressFresh(ctx, domain, name, forceRefresh)
				if err != nil {
					return nil, err
				}
				if strings.TrimSpace(addr.response.DIDAW) != stableID {
					return nil, fmt.Errorf("RegistryResolver: team member address did:aw mismatch for %s", identifier)
				}
				deliveryOrigin, err = canonicalDeliveryOrigin(keyRes, addr.response)
				if err != nil {
					return nil, fmt.Errorf("RegistryResolver: %w", err)
				}
			}
			return &ResolvedIdentity{
				DID:            keyRes.CurrentDIDKey,
				StableID:       stableID,
				Address:        address,
				Handle:         member.response.Alias,
				PublicKey:      ed25519.PublicKey(pub),
				EncryptionKey:  keyRes.EncryptionKey,
				RegistryURL:    member.authority.RegistryURL,
				DeliveryOrigin: deliveryOrigin,
				Custody:        CustodySelf,
				IdentityScope:  NormalizeIdentityScope(member.response.IdentityScope),
				ResolvedAt:     r.now().UTC(),
				ResolvedVia:    "registry",
			}, nil
		}
		pub, err := ExtractPublicKey(member.response.MemberDIDKey)
		if err != nil {
			return nil, fmt.Errorf("RegistryResolver: invalid member did:key: %w", err)
		}
		return &ResolvedIdentity{
			DID:           member.response.MemberDIDKey,
			Address:       address,
			Handle:        member.response.Alias,
			PublicKey:     ed25519.PublicKey(pub),
			RegistryURL:   member.authority.RegistryURL,
			Custody:       CustodySelf,
			IdentityScope: NormalizeIdentityScope(member.response.IdentityScope),
			ResolvedAt:    r.now().UTC(),
			ResolvedVia:   "registry",
		}, nil
	}

	domain, name, ok := splitRegistryAddress(identifier)
	if !ok {
		return nil, fmt.Errorf("RegistryResolver: invalid identifier %q", identifier)
	}
	address, err := r.resolveAddressFresh(ctx, domain, name, forceRefresh)
	if err != nil {
		return nil, err
	}
	keyRes, err := r.resolveKeyFresh(ctx, address.authority.RegistryURL, address.response.DIDAW, forceRefresh)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(keyRes.DIDAW) != address.response.DIDAW {
		return nil, fmt.Errorf("RegistryResolver: key did:aw mismatch for %s", identifier)
	}
	if strings.TrimSpace(address.response.CurrentDIDKey) != "" && address.response.CurrentDIDKey != keyRes.CurrentDIDKey {
		return nil, fmt.Errorf("RegistryResolver: address/key mismatch for %s", identifier)
	}
	r.mu.Lock()
	cachedHead := r.anchorFor(address.authority.RegistryURL, address.response.DIDAW)
	r.mu.Unlock()
	outcome, nextHead, verifyErr := VerifyDidKeyResolution(keyRes, cachedHead, r.now())
	if outcome == StableIdentityVerified && nextHead != nil {
		r.mu.Lock()
		r.headCache[headCacheKey(address.authority.RegistryURL, address.response.DIDAW)] = nextHead
		r.mu.Unlock()
	}
	if outcome == StableIdentityHardError {
		return nil, fmt.Errorf("RegistryResolver: invalid log head for %s: %w", identifier, verifyErr)
	}
	pub, err := ExtractPublicKey(keyRes.CurrentDIDKey)
	if err != nil {
		return nil, fmt.Errorf("RegistryResolver: invalid current did:key: %w", err)
	}
	deliveryOrigin, err := canonicalDeliveryOrigin(keyRes, address.response)
	if err != nil {
		return nil, fmt.Errorf("RegistryResolver: %w", err)
	}
	return &ResolvedIdentity{
		DID:            keyRes.CurrentDIDKey,
		StableID:       keyRes.DIDAW,
		Address:        domain + "/" + name,
		Handle:         name,
		ControllerDID:  address.authority.ControllerDID,
		PublicKey:      ed25519.PublicKey(pub),
		EncryptionKey:  keyRes.EncryptionKey,
		RegistryURL:    address.authority.RegistryURL,
		DeliveryOrigin: deliveryOrigin,
		Custody:        CustodySelf,
		IdentityScope:  IdentityModeGlobal,
		ResolvedAt:     r.now().UTC(),
		ResolvedVia:    "registry",
	}, nil
}

func canonicalDeliveryOrigin(keyRes *DidKeyResolution, address *registryAddressResponse) (string, error) {
	_ = keyRes // Current-key resolution verifies identity binding only; route origin belongs to the address route.
	if address != nil && address.Delivery != nil {
		return strings.TrimSpace(address.Delivery.Origin), nil
	}
	return "", nil
}

func (r *RegistryResolver) VerifyStableIdentity(ctx context.Context, address, stableID string) *StableIdentityVerification {
	return r.VerifyStableIdentityCurrent(ctx, address, stableID, "")
}

func (r *RegistryResolver) VerifyStableIdentityCurrent(ctx context.Context, address, stableID, expectedCurrentDIDKey string) *StableIdentityVerification {
	return r.VerifyStableIdentityCheckpointed(ctx, address, stableID, expectedCurrentDIDKey, nil)
}

// VerifyStableIdentityCheckpointed is VerifyStableIdentityCurrent against the
// caller's anti-rollback checkpoint for the registry that answers: checkpoint
// is asked for that registry before verifying. The result names the registry,
// and whether it had no checkpoint for this identity (NewCheckpoint).
func (r *RegistryResolver) VerifyStableIdentityCheckpointed(ctx context.Context, address, stableID, expectedCurrentDIDKey string, checkpoint func(registryURL string) *VerifiedLogHead) *StableIdentityVerification {
	domain, name, ok := splitRegistryAddress(address)
	if !ok || strings.TrimSpace(stableID) == "" {
		return &StableIdentityVerification{Outcome: StableIdentityDegraded}
	}
	addr, err := r.resolveAddress(ctx, domain, name)
	if err != nil {
		return &StableIdentityVerification{
			Outcome: StableIdentityDegraded,
			Error:   err.Error(),
		}
	}
	if addr.response.DIDAW != stableID {
		readKey := "address:" + domain + "/" + name
		allowed, lastFailed := r.claimForcedRead(readKey)
		if !allowed && lastFailed {
			return &StableIdentityVerification{Outcome: StableIdentityStaleCache, Error: "registry address could not be read again in this interval"}
		}
		if allowed {
			addr, err = r.resolveAddressFresh(ctx, domain, name, true)
			r.recordForcedRead(readKey, err != nil)
			if err != nil {
				return &StableIdentityVerification{Outcome: StableIdentityStaleCache, Error: err.Error()}
			}
		}
		if addr.response.DIDAW != stableID {
			return &StableIdentityVerification{
				Outcome: StableIdentityHardError,
				Error:   "registry address did:aw mismatch",
			}
		}
	}
	registryURL := addr.authority.RegistryURL
	newCheckpoint := r.seedCheckpoint(registryURL, stableID, checkpoint)
	result := r.verifyStableIdentityAtRegistry(ctx, registryURL, stableID, expectedCurrentDIDKey, false)
	result.RegistryURL = registryURL
	result.NewCheckpoint = newCheckpoint
	return result
}

func (r *RegistryResolver) verifyStableIdentityAtRegistry(ctx context.Context, registryURL, stableID, expectedCurrentDIDKey string, fresh bool) *StableIdentityVerification {
	keyRes, err := r.resolveKeyFresh(ctx, registryURL, stableID, fresh)
	if err != nil {
		return &StableIdentityVerification{
			Outcome: StableIdentityDegraded,
			Error:   err.Error(),
		}
	}
	expectedCurrentDIDKey = strings.TrimSpace(expectedCurrentDIDKey)
	if expectedCurrentDIDKey != "" && strings.TrimSpace(keyRes.CurrentDIDKey) != expectedCurrentDIDKey && !fresh {
		staleCurrentDIDKey := keyRes.CurrentDIDKey
		readKey := "key:" + registryURL + "|" + stableID
		allowed, lastFailed := r.claimForcedRead(readKey)
		if !allowed && lastFailed {
			return &StableIdentityVerification{
				Outcome:       StableIdentityStaleCache,
				CurrentDIDKey: staleCurrentDIDKey,
				Error:         "registry key could not be read again in this interval",
			}
		}
		if allowed {
			keyRes, err = r.resolveKeyFresh(ctx, registryURL, stableID, true)
			r.recordForcedRead(readKey, err != nil)
			if err != nil {
				return &StableIdentityVerification{
					Outcome:       StableIdentityStaleCache,
					CurrentDIDKey: staleCurrentDIDKey,
					Error:         err.Error(),
				}
			}
		}
	}
	if strings.TrimSpace(keyRes.DIDAW) != stableID {
		return &StableIdentityVerification{
			Outcome: StableIdentityHardError,
			Error:   "registry key did:aw mismatch",
		}
	}

	r.mu.Lock()
	cachedHead := r.anchorFor(registryURL, stableID)
	r.mu.Unlock()

	if cachedHead == nil {
		return r.verifyStableIdentityViaFullLog(ctx, registryURL, stableID, keyRes.CurrentDIDKey)
	}

	outcome, nextHead, verifyErr := VerifyDidKeyResolution(keyRes, cachedHead, r.now())
	if outcome == StableIdentityVerified && nextHead != nil {
		r.mu.Lock()
		r.headCache[headCacheKey(registryURL, stableID)] = nextHead
		r.mu.Unlock()
	}
	if outcome == StableIdentityDegraded && verifyErr == nil {
		return r.verifyStableIdentityViaFullLog(ctx, registryURL, stableID, keyRes.CurrentDIDKey)
	}
	if verifyErr != nil {
		return &StableIdentityVerification{
			Outcome:       outcome,
			CurrentDIDKey: keyRes.CurrentDIDKey,
			Error:         verifyErr.Error(),
		}
	}
	return &StableIdentityVerification{
		Outcome:       outcome,
		CurrentDIDKey: keyRes.CurrentDIDKey,
		VerifiedHead:  nextHead,
	}
}

// headCacheKey scopes a verified log head to the registry that served it:
// a checkpoint is one registry's view, and a move to another registry starts
// a new one (docs/trust-model.md).
func headCacheKey(registryURL, stableID string) string {
	return strings.TrimRight(strings.TrimSpace(registryURL), "/") + "|" + strings.TrimSpace(stableID)
}

// anyRegistryAnchor is the key of an anchor seeded without a registry, through
// the released SeedVerifiedHead.
func anyRegistryAnchor(stableID string) string {
	return headCacheKey("*", stableID)
}

// anchorFor is the anti-rollback anchor for stableID at registryURL: the
// higher of the one verified or seeded there and one seeded without a
// registry, so the released SeedVerifiedHead advances a resolver that already
// holds a lower anchor, as before anchors were kept per registry.
func (r *RegistryResolver) anchorFor(registryURL, stableID string) *VerifiedLogHead {
	scoped := r.headCache[headCacheKey(registryURL, stableID)]
	released := r.headCache[anyRegistryAnchor(stableID)]
	if released != nil && (scoped == nil || released.Seq > scoped.Seq) {
		return released
	}
	return scoped
}

// SeedVerifiedHeadAt installs a previously verified log head as the
// anti-rollback anchor for stableID at registryURL. Callers restore it from the
// persisted checkpoint so a restart does not forget which sequence was already
// verified — without it a registry can serve a valid truncated prefix and roll
// a rotated identity back to a retired key (default-aajc.8). Seeding never
// moves the anchor backwards: a lower or equal sequence is ignored.
func (r *RegistryResolver) SeedVerifiedHeadAt(registryURL, stableID string, head *VerifiedLogHead) {
	r.seedAnchor(headCacheKey(registryURL, stableID), stableID, head)
}

// SeedVerifiedHead is the released form (aw-v1.36.58), kept for Go callers of
// this public package: it seeds an anchor for stableID that applies at every
// registry, and wins over a registry's own anchor when its sequence is higher
// (anchorFor), which is what the anchor meant before anchors were kept per
// registry.
func (r *RegistryResolver) SeedVerifiedHead(stableID string, head *VerifiedLogHead) {
	r.seedAnchor(anyRegistryAnchor(stableID), stableID, head)
}

func (r *RegistryResolver) seedAnchor(key, stableID string, head *VerifiedLogHead) {
	if strings.TrimSpace(stableID) == "" || head == nil || head.Seq < 1 || !isLowerHex(strings.TrimSpace(head.EntryHash)) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.headCache[key]; existing != nil && existing.Seq >= head.Seq {
		return
	}
	r.headCache[key] = head
}

// seedCheckpoint installs the caller's persisted checkpoint for registryURL
// (seeding only ever advances the in-memory anchor). It reports whether the
// caller holds no checkpoint for this identity at that registry: a new
// checkpoint. A head this resolver cached while resolving the same message is
// not a checkpoint.
func (r *RegistryResolver) seedCheckpoint(registryURL, stableID string, checkpoint func(registryURL string) *VerifiedLogHead) bool {
	if checkpoint == nil {
		return true
	}
	head := checkpoint(registryURL)
	if head == nil {
		return true
	}
	r.SeedVerifiedHeadAt(registryURL, stableID, head)
	return false
}

func (r *RegistryResolver) verifyStableIdentityViaFullLog(ctx context.Context, registryURL, stableID, currentDIDKey string) *StableIdentityVerification {
	entries, err := r.fetchDIDLog(ctx, registryURL, stableID)
	if err != nil {
		return &StableIdentityVerification{
			Outcome:       StableIdentityDegraded,
			CurrentDIDKey: currentDIDKey,
			Error:         err.Error(),
		}
	}
	head, err := VerifyDidLogEntries(stableID, entries, r.now())
	if err != nil {
		return &StableIdentityVerification{
			Outcome:       StableIdentityHardError,
			CurrentDIDKey: currentDIDKey,
			Error:         err.Error(),
		}
	}
	if head == nil {
		return &StableIdentityVerification{
			Outcome:       StableIdentityDegraded,
			CurrentDIDKey: currentDIDKey,
			Error:         "missing verified audit log head",
		}
	}
	if strings.TrimSpace(head.CurrentDIDKey) != strings.TrimSpace(currentDIDKey) {
		return &StableIdentityVerification{
			Outcome:       StableIdentityHardError,
			CurrentDIDKey: currentDIDKey,
			Error:         "audit log current did:key mismatch",
		}
	}
	// A log that verifies from genesis is still not acceptable if it contradicts
	// what we already verified: it must CONTAIN our checkpoint entry and extend
	// it. Otherwise a registry can serve a valid truncated prefix (rollback to a
	// retired key) or a valid fork that never included our entry
	// (default-aajc.8).
	r.mu.Lock()
	checkpoint := r.anchorFor(registryURL, stableID)
	r.mu.Unlock()
	if checkpoint != nil {
		if head.Seq < checkpoint.Seq {
			return &StableIdentityVerification{
				Outcome:       StableIdentityHardError,
				CurrentDIDKey: currentDIDKey,
				Error:         "audit log behind verified checkpoint",
			}
		}
		if !didLogContainsEntry(entries, checkpoint.Seq, checkpoint.EntryHash) {
			return &StableIdentityVerification{
				Outcome:       StableIdentityHardError,
				CurrentDIDKey: currentDIDKey,
				Error:         "audit log does not extend verified checkpoint",
			}
		}
	}
	r.mu.Lock()
	r.headCache[headCacheKey(registryURL, stableID)] = head
	r.mu.Unlock()
	return &StableIdentityVerification{
		Outcome:       StableIdentityVerified,
		CurrentDIDKey: currentDIDKey,
		VerifiedHead:  head,
	}
}

func (r *RegistryResolver) resolveAddress(ctx context.Context, domain, name string) (*registryAddressCacheValue, error) {
	return r.resolveAddressFresh(ctx, domain, name, false)
}

func (r *RegistryResolver) resolveAddressFresh(ctx context.Context, domain, name string, forceRefresh bool) (*registryAddressCacheValue, error) {
	cacheKey := domain + "/" + name
	if !forceRefresh {
		if cached, ok := r.loadAddressCache(cacheKey); ok {
			return cached, nil
		}
	}
	authority, err := r.discoverAuthority(ctx, domain)
	if err != nil {
		return nil, err
	}
	var resp registryAddressResponse
	if err := r.getAddressJSON(ctx, authority.RegistryURL, domain, name, forceRefresh, &resp); err != nil {
		return nil, err
	}
	value := &registryAddressCacheValue{
		authority: authority,
		response:  &resp,
	}
	r.storeAddressCache(cacheKey, value, registryAddressTTL)
	return value, nil
}

func (r *RegistryResolver) resolveTeamMemberFresh(ctx context.Context, teamID, alias string, forceRefresh bool) (*registryTeamMemberCacheValue, error) {
	cacheKey := teamID + "/" + alias
	if !forceRefresh {
		if cached, ok := r.loadMemberCache(cacheKey); ok {
			return cached, nil
		}
	}
	domain, name, err := ParseTeamID(teamID)
	if err != nil {
		return nil, fmt.Errorf("RegistryResolver: invalid team member reference %q: %w", cacheKey, err)
	}
	authority, err := r.discoverAuthority(ctx, domain)
	if err != nil {
		return nil, err
	}
	var resp registryTeamMemberResponse
	memberPath := "/v1/namespaces/" + urlPathEscape(domain) + "/teams/" + urlPathEscape(name) + "/members/" + urlPathEscape(alias)
	headers := optionalSignedPathHeaders(http.MethodGet, memberPath, r.TeamReadSigningKey)
	if forceRefresh {
		if headers == nil {
			headers = make(map[string]string)
		}
		headers["Cache-Control"] = "no-cache"
	}
	if err := r.getJSONWithHeaders(ctx, authority.RegistryURL, memberPath, headers, &resp); err != nil {
		return nil, err
	}
	value := &registryTeamMemberCacheValue{
		authority: authority,
		response:  &resp,
	}
	r.storeMemberCache(cacheKey, value, registryAddressTTL)
	return value, nil
}

func (r *RegistryResolver) resolveKeyFresh(ctx context.Context, registryURL, didAW string, forceRefresh bool) (*DidKeyResolution, error) {
	if !forceRefresh {
		if cached, ok := r.loadKeyCache(didAW); ok {
			return cached, nil
		}
	}
	var wire didKeyResolutionWire
	var err error
	if forceRefresh {
		err = r.getJSONWithHeaders(ctx, registryURL, "/v1/did/"+urlPathEscape(didAW)+"/key", map[string]string{"Cache-Control": "no-cache"}, &wire)
	} else {
		err = r.getJSON(ctx, registryURL, "/v1/did/"+urlPathEscape(didAW)+"/key", &wire)
	}
	if err != nil {
		return nil, err
	}
	res := &DidKeyResolution{
		idTree:          wire.idTreeEnrollment(),
		idTreeFetchedAt: r.now(),
		DIDAW:           wire.DIDAW,
		CurrentDIDKey:   wire.CurrentDIDKey,
		EncryptionKey:   wire.EncryptionKey,
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
	if res.EncryptionKey != nil {
		if err := VerifyEncryptionKeyAssertion(res.EncryptionKey, res.CurrentDIDKey, res.DIDAW, r.now()); err != nil {
			return nil, fmt.Errorf("RegistryResolver: invalid encryption key assertion for %s: %w", didAW, err)
		}
	}
	r.storeKeyCache(didAW, res, registryKeyTTL)
	return res, nil
}

func (r *RegistryResolver) fetchDIDLog(ctx context.Context, registryURL, didAW string) ([]DidKeyEvidence, error) {
	var out []DidKeyEvidence
	if err := r.getJSON(ctx, registryURL, "/v1/did/"+urlPathEscape(strings.TrimSpace(didAW))+"/log", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *RegistryResolver) discoverRegistry(ctx context.Context, domain string) (string, error) {
	authority, err := r.discoverAuthority(ctx, domain)
	if err != nil {
		return "", err
	}
	return authority.RegistryURL, nil
}

func (r *RegistryResolver) DiscoverRegistry(ctx context.Context, domain string) (string, error) {
	if strings.TrimSpace(r.fallbackRegistryURL) != "" {
		return r.fallbackRegistryURL, nil
	}
	return r.discoverRegistry(ctx, domain)
}

func (r *RegistryResolver) discoverAuthority(ctx context.Context, domain string) (DomainAuthority, error) {
	domain = canonicalizeDomain(domain)
	fallback := strings.TrimSpace(r.fallbackRegistryURL)
	if fallback != "" && (r.identityDomain == "" || domain == r.identityDomain) {
		return DomainAuthority{RegistryURL: fallback}, nil
	}
	if cached, ok := r.loadRegistryCache(domain); ok {
		return cached, nil
	}
	authority, err := DiscoverAuthoritativeRegistry(ctx, r.DNSResolver, domain)
	if err != nil {
		if fallback != "" && isDNSFallbackFailure(err) {
			return DomainAuthority{RegistryURL: fallback}, nil
		}
		return DomainAuthority{}, err
	}
	if strings.TrimSpace(authority.ControllerDID) == "" && fallback != "" {
		authority.RegistryURL = fallback
	}
	if strings.TrimSpace(authority.RegistryURL) == "" {
		authority.RegistryURL = DefaultAWIDRegistryURL
	}
	r.storeRegistryCache(domain, authority, registryDiscoveryTTL)
	return authority, nil
}

func (r *RegistryResolver) getAddressJSON(ctx context.Context, baseURL, domain, name string, bypassCache bool, out any) error {
	path := "/v1/namespaces/" + urlPathEscape(domain) + "/addresses/" + urlPathEscape(name)
	if bypassCache {
		return r.getJSONWithHeaders(ctx, baseURL, path, map[string]string{"Cache-Control": "no-cache"}, out)
	}
	return r.getJSON(ctx, baseURL, path, out)
}

func (r *RegistryResolver) getJSON(ctx context.Context, baseURL, path string, out any) error {
	return r.getJSONWithHeaders(ctx, baseURL, path, nil, out)
}

func (r *RegistryResolver) getJSONWithHeaders(ctx context.Context, baseURL, path string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := DoNoRedirectWithTimeout(r.httpClientFor(baseURL), req, APITimeout())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(resp, readBodyString(resp))
	}
	data, err := ReadAllBounded(resp.Body, MaxResponseSize)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func readBodyString(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	data := []byte(ReadErrorExcerpt(resp.Body))
	var body map[string]any
	if err := json.Unmarshal(data, &body); err == nil {
		if detail, ok := body["detail"].(string); ok && strings.TrimSpace(detail) != "" {
			return SanitizeErrorText(detail)
		}
	}
	return strings.TrimSpace(string(data))
}

func (r *RegistryResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func splitRegistryAddress(identifier string) (string, string, bool) {
	identifier = strings.TrimSpace(identifier)
	domain, name, ok := strings.Cut(identifier, "/")
	if !ok {
		return "", "", false
	}
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	if domain == "" || name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return domain, name, true
}

func splitTeamMemberReference(identifier string) (teamID, alias string, ok bool) {
	identifier = strings.TrimSpace(identifier)
	teamID, alias, ok = strings.Cut(identifier, "/")
	if !ok {
		return "", "", false
	}
	if _, _, err := ParseTeamID(teamID); err != nil {
		return "", "", false
	}
	alias = strings.TrimSpace(alias)
	if alias == "" || strings.Contains(alias, "/") {
		return "", "", false
	}
	return strings.TrimSpace(teamID), alias, true
}

func (r *RegistryResolver) loadRegistryCache(domain string) (DomainAuthority, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.registryCache[domain]
	if !ok || r.now().After(entry.expiresAt) {
		delete(r.registryCache, domain)
		return DomainAuthority{}, false
	}
	return entry.value, true
}

func isDNSFallbackFailure(err error) bool {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return false
	}
	if dnsErr.IsTimeout || dnsErr.IsTemporary {
		return true
	}
	detail := strings.ToLower(strings.TrimSpace(dnsErr.Err))
	return strings.Contains(detail, "connection refused") ||
		strings.Contains(detail, "network is unreachable") ||
		strings.Contains(detail, "no route to host")
}

func (r *RegistryResolver) storeRegistryCache(domain string, authority DomainAuthority, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registryCache[domain] = cachedValue[DomainAuthority]{value: authority, expiresAt: r.now().Add(ttl)}
}

func (r *RegistryResolver) loadAddressCache(key string) (*registryAddressCacheValue, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.addressCache[key]
	if !ok || r.now().After(entry.expiresAt) {
		delete(r.addressCache, key)
		return nil, false
	}
	return entry.value, true
}

func (r *RegistryResolver) storeAddressCache(key string, value *registryAddressCacheValue, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addressCache[key] = cachedValue[*registryAddressCacheValue]{value: value, expiresAt: r.now().Add(ttl)}
}

func (r *RegistryResolver) loadMemberCache(key string) (*registryTeamMemberCacheValue, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.memberCache[key]
	if !ok || r.now().After(entry.expiresAt) {
		delete(r.memberCache, key)
		return nil, false
	}
	return entry.value, true
}

func (r *RegistryResolver) storeMemberCache(key string, value *registryTeamMemberCacheValue, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.memberCache[key] = cachedValue[*registryTeamMemberCacheValue]{value: value, expiresAt: r.now().Add(ttl)}
}

func (r *RegistryResolver) loadKeyCache(didAW string) (*DidKeyResolution, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.keyCache[didAW]
	if !ok || r.now().After(entry.expiresAt) {
		delete(r.keyCache, didAW)
		return nil, false
	}
	return entry.value, true
}

func (r *RegistryResolver) storeKeyCache(didAW string, value *DidKeyResolution, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keyCache[didAW] = cachedValue[*DidKeyResolution]{value: value, expiresAt: r.now().Add(ttl)}
}

// didLogContainsEntry reports whether the served log carries the exact entry we
// previously verified at seq, identifying a truncated prefix or a forked log
// that dropped it.
func didLogContainsEntry(entries []DidKeyEvidence, seq int, entryHash string) bool {
	entryHash = strings.TrimSpace(entryHash)
	if entryHash == "" {
		return false
	}
	for i := range entries {
		if entries[i].Seq == seq {
			return strings.TrimSpace(entries[i].EntryHash) == entryHash
		}
	}
	return false
}
