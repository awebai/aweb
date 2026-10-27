package awid

// The cached identity-tree status client for aw (docs/id-certificates.md §4),
// one policy with the Python CachedRegistryClient. Its cache is in-process
// only: evidence is aged on this process's whole-second clock, an entry
// stamped ahead of that clock is neither fresh nor last-known-good, and ages
// are never clamped.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const (
	idStatusPath            = "/v1/id-certificates/status"
	idStatusFreshSeconds    = 60
	idStatusCooldownSeconds = idStatusFreshSeconds
	// An entry older than this is neither fresh nor last-known-good.
	idStatusRetentionSeconds = 2 * IDStatusOutageGraceSeconds
	// IDStatusOutageGraceSeconds bounds last-known-good evidence after a failed refresh.
	IDStatusOutageGraceSeconds = 900
)

// ErrMalformedIDStatus is a successful status answer that is not a JSON
// object within the response size bound.
var ErrMalformedIDStatus = errors.New("malformed identity-tree status answer")

// IDStatusClient reads identity-tree status for the chain verifier. Evidence
// aged 60 seconds or less is reused with no DNS or HTTP work. Older evidence
// waits for one refresh shared by every caller of the same request; when it
// fails, last-known-good evidence is returned with its true age and
// refresh_failed, and with none, without an age. After a failed attempt its
// domain makes no attempt for 60 seconds.
type IDStatusClient struct {
	Registry *RegistryClient
	// Authority reads the domain's exact _awid TXT authority.
	Authority func(ctx context.Context, domain string) (DomainAuthority, error)
	// Route finds the registry the domain routes to.
	Route func(ctx context.Context, domain string) (string, error)
	// Timeout bounds DNS, routing and HTTP of one attempt together.
	Timeout time.Duration
	// Now is this process's clock in whole seconds.
	Now func() int64

	mu       sync.Mutex
	entries  map[string]*idStatusEntry
	inflight map[string]*idStatusAttempt
	failedAt map[string]int64
}

type idStatusEntry struct {
	fetchedAt int64
	status    map[string]any
	authority map[string]any
}

type idStatusAttempt struct {
	done   chan struct{}
	entry  *idStatusEntry
	failed bool
	age    int64
}

// NewIDStatusClient reads status through registry and DNS authority through resolver.
func NewIDStatusClient(registry *RegistryClient, resolver TXTResolver) *IDStatusClient {
	return &IDStatusClient{
		Registry: registry,
		Authority: func(ctx context.Context, domain string) (DomainAuthority, error) {
			return VerifyExactDomainAuthority(ctx, resolver, domain)
		},
		Route:   registry.DiscoverRegistry,
		Timeout: 5 * time.Second,
	}
}

func (c *IDStatusClient) now() int64 {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().Unix()
}

// FetchIDCertificateStatus POSTs a status request to the registry domain
// routes to. A refused answer is a *RegistryError; a successful answer that is
// not a JSON object is ErrMalformedIDStatus.
func (c *IDStatusClient) FetchIDCertificateStatus(ctx context.Context, domain string, request map[string]any) (map[string]any, error) {
	registryURL, err := c.Route(ctx, domain)
	if err != nil {
		return nil, err
	}
	req, err := c.Registry.newRequest(ctx, "POST", registryURL, idStatusPath, nil, request)
	if err != nil {
		return nil, err
	}
	resp, err := DoNoRedirectWithTimeout(c.Registry.httpClient(), req, APITimeout())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseRegistryError(resp)
	}
	// A successful answer that cannot be read in full, within the bound, as
	// one JSON object is malformed, not an outage.
	body, err := ReadAllBounded(resp.Body, MaxResponseSize)
	if err != nil {
		return nil, ErrMalformedIDStatus
	}
	var status map[string]any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&status); err != nil || status == nil || d.More() {
		return nil, ErrMalformedIDStatus
	}
	return status, nil
}

// IDChainEvidence is trusted status evidence for verifying subject's chain in
// domain. Fetch failures never surface as errors.
func (c *IDStatusClient) IDChainEvidence(ctx context.Context, bundle map[string]any, subject IDChainSubject, domain string) *IDChainEvidence {
	request, err := IDStatusRequest(bundle, subject, domain)
	if err != nil || request == nil {
		// The verifier refuses this request before it reads any evidence.
		return &IDChainEvidence{Status: map[string]any{}, NamespaceAuthority: map[string]any{}}
	}
	key, err := idStatusCacheKey(request)
	if err != nil {
		return &IDChainEvidence{Status: map[string]any{}, NamespaceAuthority: map[string]any{}}
	}
	readAt := c.now()
	cached := c.cachedEntry(key, readAt)
	if cached != nil && readAt-cached.fetchedAt <= idStatusFreshSeconds {
		return idStatusEvidence(cached, readAt-cached.fetchedAt, false)
	}
	attempt := c.attempt(key, request)
	select {
	case <-attempt.done:
	case <-ctx.Done():
		return &IDChainEvidence{Status: map[string]any{}, NamespaceAuthority: map[string]any{}}
	}
	if attempt.entry != nil {
		return idStatusEvidence(attempt.entry, attempt.age, false)
	}
	if attempt.failed && cached != nil {
		// Aged through the wait for the failed attempt.
		return idStatusEvidence(cached, c.now()-cached.fetchedAt, true)
	}
	return &IDChainEvidence{Status: map[string]any{}, NamespaceAuthority: map[string]any{}, RefreshFailed: attempt.failed}
}

// cachedEntry returns the stored entry unless it is stamped ahead of the
// clock, whose age is then unknown, or past retention.
func (c *IDStatusClient) cachedEntry(key string, now int64) *idStatusEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	if entry == nil {
		return nil
	}
	if now < entry.fetchedAt || now-entry.fetchedAt > idStatusRetentionSeconds {
		delete(c.entries, key)
		return nil
	}
	return entry
}

// attempt joins the in-flight refresh for key or starts one. The refresh runs
// detached from any caller, so a cancelled caller leaves it running for the
// others. During its domain's cooldown no attempt is made.
func (c *IDStatusClient) attempt(key string, request map[string]any) *idStatusAttempt {
	domain := request["domain"].(string)
	c.mu.Lock()
	defer c.mu.Unlock()
	if a := c.inflight[key]; a != nil {
		return a
	}
	a := &idStatusAttempt{done: make(chan struct{})}
	if failedAt, ok := c.failedAt[domain]; ok {
		if since := c.now() - failedAt; since >= 0 && since <= idStatusCooldownSeconds {
			a.failed = true
			close(a.done)
			return a
		}
	}
	if c.inflight == nil {
		c.inflight = map[string]*idStatusAttempt{}
	}
	c.inflight[key] = a
	go c.refresh(key, domain, request, a)
	return a
}

// refresh makes one attempt, with DNS authority, routing and HTTP under one
// timeout. The entry is stamped when the attempt began. A malformed
// successful answer is not an outage: it removes the entry, so no older tree
// outlives it.
func (c *IDStatusClient) refresh(key, domain string, request map[string]any, a *idStatusAttempt) {
	started := c.now()
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	authority, err := c.Authority(ctx, domain)
	var status map[string]any
	if err == nil {
		status, err = c.FetchIDCertificateStatus(ctx, domain, request)
	}
	c.mu.Lock()
	defer func() {
		delete(c.inflight, key)
		c.mu.Unlock()
		close(a.done)
	}()
	switch {
	case errors.Is(err, ErrMalformedIDStatus):
		delete(c.failedAt, domain)
		delete(c.entries, key)
	case err != nil:
		if c.failedAt == nil {
			c.failedAt = map[string]int64{}
		}
		c.failedAt[domain] = c.now()
		a.failed = true
	default:
		delete(c.failedAt, domain)
		entry := &idStatusEntry{
			fetchedAt: started,
			status:    status,
			authority: map[string]any{"domain": domain, "dns_name": authority.DNSName, "inherited": authority.Inherited, "controller_key": authority.ControllerDID},
		}
		if c.entries == nil {
			c.entries = map[string]*idStatusEntry{}
		}
		c.entries[key] = entry
		a.entry = entry
		a.age = c.now() - started
	}
}

func idStatusCacheKey(request map[string]any) (string, error) {
	raw, err := CanonicalJSONValue(request)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(raw))
	return request["domain"].(string) + ":" + hex.EncodeToString(sum[:]), nil
}

// idStatusEvidence never clamps the age: a negative one is unavailable
// evidence to the verifier.
func idStatusEvidence(entry *idStatusEntry, age int64, refreshFailed bool) *IDChainEvidence {
	seconds := float64(age)
	return &IDChainEvidence{Status: entry.status, NamespaceAuthority: entry.authority, AgeSeconds: &seconds, RefreshFailed: refreshFailed}
}
