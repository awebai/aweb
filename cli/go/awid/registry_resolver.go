package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	registryDiscoveryTTL = 15 * time.Minute
	registryAddressTTL   = 5 * time.Minute
	registryKeyTTL       = 15 * time.Minute
)

type cachedValue[T any] struct {
	value     T
	expiresAt time.Time
}

type registryAddressResponse struct {
	AddressID     string `json:"address_id"`
	Domain        string `json:"domain"`
	Name          string `json:"name"`
	DIDAW         string `json:"did_aw"`
	CurrentDIDKey string `json:"current_did_key"`
	Reachability  string `json:"reachability"`
	CreatedAt     string `json:"created_at"`
}

type registryTeamMemberResponse struct {
	TeamID        string `json:"team_id"`
	CertificateID string `json:"certificate_id"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw"`
	MemberAddress string `json:"member_address"`
	Alias         string `json:"alias"`
	Lifetime      string `json:"lifetime"`
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
	DIDAW         string              `json:"did_aw"`
	CurrentDIDKey string              `json:"current_did_key"`
	LogHead       *didKeyEvidenceWire `json:"log_head"`
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
	HTTPClient          *http.Client
	DNSResolver         TXTResolver
	Now                 func() time.Time
	fallbackRegistryURL string

	mu            sync.Mutex
	registryCache map[string]cachedValue[DomainAuthority]
	addressCache  map[string]cachedValue[*registryAddressCacheValue]
	memberCache   map[string]cachedValue[*registryTeamMemberCacheValue]
	keyCache      map[string]cachedValue[*DidKeyResolution]
	headCache     map[string]*VerifiedLogHead
}

func NewRegistryResolver(httpClient *http.Client, dnsResolver TXTResolver) *RegistryResolver {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
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
	}
}

func (r *RegistryResolver) SetFallbackRegistryURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		r.fallbackRegistryURL = ""
		return nil
	}
	canonical, err := canonicalRegistryServerOrigin(raw)
	if err != nil {
		return err
	}
	r.fallbackRegistryURL = canonical
	return nil
}

func (r *RegistryResolver) Resolve(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	if teamID, alias, ok := splitTeamMemberReference(identifier); ok {
		member, err := r.resolveTeamMember(ctx, teamID, alias)
		if err != nil {
			return nil, err
		}
		address := strings.TrimSpace(member.response.MemberAddress)
		if address == "" {
			address = strings.TrimSpace(identifier)
		}
		if stableID := strings.TrimSpace(member.response.MemberDIDAW); stableID != "" {
			keyRes, err := r.resolveKey(ctx, member.authority.RegistryURL, stableID)
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
			return &ResolvedIdentity{
				DID:         keyRes.CurrentDIDKey,
				StableID:    stableID,
				Address:     address,
				Handle:      member.response.Alias,
				PublicKey:   ed25519.PublicKey(pub),
				RegistryURL: member.authority.RegistryURL,
				Custody:     CustodySelf,
				Lifetime:    member.response.Lifetime,
				ResolvedAt:  r.now().UTC(),
				ResolvedVia: "registry",
			}, nil
		}
		pub, err := ExtractPublicKey(member.response.MemberDIDKey)
		if err != nil {
			return nil, fmt.Errorf("RegistryResolver: invalid member did:key: %w", err)
		}
		return &ResolvedIdentity{
			DID:         member.response.MemberDIDKey,
			Address:     address,
			Handle:      member.response.Alias,
			PublicKey:   ed25519.PublicKey(pub),
			RegistryURL: member.authority.RegistryURL,
			Custody:     CustodySelf,
			Lifetime:    member.response.Lifetime,
			ResolvedAt:  r.now().UTC(),
			ResolvedVia: "registry",
		}, nil
	}

	domain, name, ok := splitRegistryAddress(identifier)
	if !ok {
		return nil, fmt.Errorf("RegistryResolver: invalid identifier %q", identifier)
	}
	address, err := r.resolveAddress(ctx, domain, name)
	if err != nil {
		return nil, err
	}
	keyRes, err := r.resolveKey(ctx, address.authority.RegistryURL, address.response.DIDAW)
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
	cachedHead := r.headCache[address.response.DIDAW]
	r.mu.Unlock()
	outcome, nextHead, verifyErr := VerifyDidKeyResolution(keyRes, cachedHead, r.now())
	if outcome == StableIdentityVerified && nextHead != nil {
		r.mu.Lock()
		r.headCache[address.response.DIDAW] = nextHead
		r.mu.Unlock()
	}
	if outcome == StableIdentityHardError {
		return nil, fmt.Errorf("RegistryResolver: invalid log head for %s: %w", identifier, verifyErr)
	}
	pub, err := ExtractPublicKey(keyRes.CurrentDIDKey)
	if err != nil {
		return nil, fmt.Errorf("RegistryResolver: invalid current did:key: %w", err)
	}
	return &ResolvedIdentity{
		DID:           keyRes.CurrentDIDKey,
		StableID:      keyRes.DIDAW,
		Address:       domain + "/" + name,
		Handle:        name,
		ControllerDID: address.authority.ControllerDID,
		PublicKey:     ed25519.PublicKey(pub),
		RegistryURL:   address.authority.RegistryURL,
		Custody:       CustodySelf,
		Lifetime:      LifetimePersistent,
		ResolvedAt:    r.now().UTC(),
		ResolvedVia:   "registry",
	}, nil
}

func (r *RegistryResolver) VerifyStableIdentity(ctx context.Context, address, stableID string) *StableIdentityVerification {
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
		return &StableIdentityVerification{
			Outcome: StableIdentityHardError,
			Error:   "registry address did:aw mismatch",
		}
	}
	keyRes, err := r.resolveKey(ctx, addr.authority.RegistryURL, stableID)
	if err != nil {
		return &StableIdentityVerification{
			Outcome: StableIdentityDegraded,
			Error:   err.Error(),
		}
	}
	if strings.TrimSpace(keyRes.DIDAW) != stableID {
		return &StableIdentityVerification{
			Outcome: StableIdentityHardError,
			Error:   "registry key did:aw mismatch",
		}
	}

	r.mu.Lock()
	cachedHead := r.headCache[stableID]
	r.mu.Unlock()

	outcome, nextHead, verifyErr := VerifyDidKeyResolution(keyRes, cachedHead, r.now())
	if outcome == StableIdentityVerified && nextHead != nil {
		r.mu.Lock()
		r.headCache[stableID] = nextHead
		r.mu.Unlock()
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
	}
}

func (r *RegistryResolver) resolveAddress(ctx context.Context, domain, name string) (*registryAddressCacheValue, error) {
	cacheKey := domain + "/" + name
	if cached, ok := r.loadAddressCache(cacheKey); ok {
		return cached, nil
	}
	authority, err := r.discoverAuthority(ctx, domain)
	if err != nil {
		return nil, err
	}
	var resp registryAddressResponse
	if err := r.getJSON(ctx, authority.RegistryURL, "/v1/namespaces/"+urlPathEscape(domain)+"/addresses/"+urlPathEscape(name), &resp); err != nil {
		return nil, err
	}
	value := &registryAddressCacheValue{
		authority: authority,
		response:  &resp,
	}
	r.storeAddressCache(cacheKey, value, registryAddressTTL)
	return value, nil
}

func (r *RegistryResolver) resolveTeamMember(ctx context.Context, teamID, alias string) (*registryTeamMemberCacheValue, error) {
	cacheKey := teamID + "/" + alias
	if cached, ok := r.loadMemberCache(cacheKey); ok {
		return cached, nil
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
	if err := r.getJSON(
		ctx,
		authority.RegistryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/teams/"+urlPathEscape(name)+"/members/"+urlPathEscape(alias),
		&resp,
	); err != nil {
		return nil, err
	}
	value := &registryTeamMemberCacheValue{
		authority: authority,
		response:  &resp,
	}
	r.storeMemberCache(cacheKey, value, registryAddressTTL)
	return value, nil
}

func (r *RegistryResolver) resolveKey(ctx context.Context, registryURL, didAW string) (*DidKeyResolution, error) {
	if cached, ok := r.loadKeyCache(didAW); ok {
		return cached, nil
	}
	var wire didKeyResolutionWire
	if err := r.getJSON(ctx, registryURL, "/v1/did/"+urlPathEscape(didAW)+"/key", &wire); err != nil {
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
	r.storeKeyCache(didAW, res, registryKeyTTL)
	return res, nil
}

func (r *RegistryResolver) discoverRegistry(ctx context.Context, domain string) (string, error) {
	authority, err := r.discoverAuthority(ctx, domain)
	if err != nil {
		return "", err
	}
	return authority.RegistryURL, nil
}

func (r *RegistryResolver) DiscoverRegistry(ctx context.Context, domain string) (string, error) {
	return r.discoverRegistry(ctx, domain)
}

func (r *RegistryResolver) discoverAuthority(ctx context.Context, domain string) (DomainAuthority, error) {
	domain = canonicalizeDomain(domain)
	if cached, ok := r.loadRegistryCache(domain); ok {
		return cached, nil
	}
	authority, err := DiscoverAuthoritativeRegistry(ctx, r.DNSResolver, domain)
	if err != nil {
		return DomainAuthority{}, err
	}
	if strings.TrimSpace(authority.RegistryURL) == "" {
		authority.RegistryURL = DefaultAWIDRegistryURL
	}
	if r.fallbackRegistryURL != "" {
		authority.RegistryURL = r.fallbackRegistryURL
	}
	r.storeRegistryCache(domain, authority, registryDiscoveryTTL)
	return authority, nil
}

func (r *RegistryResolver) getJSON(ctx context.Context, baseURL, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: readBodyString(resp)}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func readBodyString(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err == nil {
		if detail, ok := body["detail"].(string); ok && strings.TrimSpace(detail) != "" {
			return detail
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
