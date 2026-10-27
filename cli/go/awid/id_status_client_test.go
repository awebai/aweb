package awid

// Mirrors awid/tests/test_id_status_client.py at 5b0391ca (S2 checkpoint 6b)
// test by test. This client's cache is in-process only, so the shared-store
// clock rule reduces to: an entry stamped ahead of the clock is neither fresh
// nor last-known-good, and ages are never clamped.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const statusTestRegistry = "https://registry.test"

type statusVectors struct {
	Certificates map[string]struct {
		Signed map[string]any `json:"signed"`
	} `json:"certificates"`
	Statuses map[string]map[string]any `json:"status_fixtures"`
	Cases    []struct {
		Name    string         `json:"name"`
		Chain   []string       `json:"chain"`
		Status  string         `json:"status"`
		Subject map[string]any `json:"subject"`
		Cache   *struct {
			Age     float64 `json:"age_seconds"`
			Refresh string  `json:"refresh"`
		} `json:"cache"`
		Expected IDChainResult `json:"expected"`
	} `json:"verification_cases"`
}

func loadStatusVectors(t *testing.T) statusVectors {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "id-certificates-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v statusVectors
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// statusEnv is an AWID status endpoint and DNS whose answers and failures a
// test sets, and the clock both the client and the endpoint read.
type statusEnv struct {
	t      *testing.T
	v      statusVectors
	clock  atomic.Int64
	mu     sync.Mutex
	status map[string]map[string]any
	ctrl   map[string]string

	httpStatus         int
	rawBody            []byte
	brokenBody         bool
	dnsFailure         bool
	dnsDelay           time.Duration
	httpDelay          time.Duration
	advanceDuringFetch int64
	gate               map[string]chan struct{}

	requests   []string
	dnsLookups []string
	client     *IDStatusClient
}

func newStatusEnv(t *testing.T) *statusEnv {
	t.Helper()
	v := loadStatusVectors(t)
	env := &statusEnv{t: t, v: v, httpStatus: 200, gate: map[string]chan struct{}{}}
	env.clock.Store(1_000_000)
	normal := v.Statuses["normal"]
	env.status = map[string]map[string]any{"example.com": normal}
	env.ctrl = map[string]string{"example.com": openEpochKey(normal)}
	env.client = env.makeClient(5 * time.Second)
	return env
}

func openEpochKey(status map[string]any) string {
	epochs := status["namespace"].(map[string]any)["epochs"].([]any)
	for i := len(epochs) - 1; i >= 0; i-- {
		e := epochs[i].(map[string]any)
		if e["retired_at"] == nil {
			return e["did_key"].(string)
		}
	}
	return ""
}

func (env *statusEnv) makeClient(timeout time.Duration) *IDStatusClient {
	return &IDStatusClient{
		Registry:  &RegistryClient{DefaultRegistryURL: statusTestRegistry, HTTPClient: &http.Client{Transport: env}},
		Authority: env.verifyDomain,
		Route:     func(context.Context, string) (string, error) { return statusTestRegistry, nil },
		Timeout:   timeout,
		Now:       env.clock.Load,
	}
}

func (env *statusEnv) set(f func()) {
	env.mu.Lock()
	defer env.mu.Unlock()
	f()
}

func (env *statusEnv) counts() (int, int) {
	env.mu.Lock()
	defer env.mu.Unlock()
	return len(env.requests), len(env.dnsLookups)
}

func (env *statusEnv) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodPost || r.URL.Path != idStatusPath {
		env.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
	}
	body, _ := io.ReadAll(r.Body)
	var request struct {
		Domain string `json:"domain"`
	}
	_ = json.Unmarshal(body, &request)
	env.mu.Lock()
	env.requests = append(env.requests, request.Domain)
	gate := env.gate[request.Domain]
	delay, status, raw, advance, broken := env.httpDelay, env.httpStatus, env.rawBody, env.advanceDuringFetch, env.brokenBody
	answer := env.status[request.Domain]
	env.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	env.clock.Add(advance)
	respond := func(code int, payload []byte) *http.Response {
		return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(payload)), Request: r}
	}
	if status != 200 {
		return respond(status, []byte(`{"detail":"registry unavailable"}`)), nil
	}
	if broken {
		r := respond(200, nil)
		r.Body = io.NopCloser(io.MultiReader(strings.NewReader(`{"v":1,`), errReader{}))
		return r, nil
	}
	if raw != nil {
		return respond(200, raw), nil
	}
	encoded, _ := json.Marshal(answer)
	return respond(200, encoded), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset mid-body") }

func (env *statusEnv) verifyDomain(ctx context.Context, domain string) (DomainAuthority, error) {
	env.mu.Lock()
	env.dnsLookups = append(env.dnsLookups, domain)
	delay, failure, controller := env.dnsDelay, env.dnsFailure, env.ctrl[domain]
	env.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return DomainAuthority{}, ctx.Err()
		}
	}
	if failure {
		return DomainAuthority{}, fmt.Errorf("no TXT records found for _awid.%s", domain)
	}
	return DomainAuthority{ControllerDID: controller, RegistryURL: statusTestRegistry, DNSName: "_awid." + domain}, nil
}

func (env *statusEnv) bundle(names ...string) map[string]any {
	var certs []any
	for _, n := range names {
		certs = append(certs, env.v.Certificates[n].Signed)
	}
	return map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certs}
}

var statusSubject = IDChainSubject{ID: "did:key:z6Mkon22vwz9JoNpGDxCrGZRgeNFTdRTwXYYN3fvAhA3K19x", DIDKey: "did:key:z6Mkon22vwz9JoNpGDxCrGZRgeNFTdRTwXYYN3fvAhA3K19x", TeamMemberDIDKey: "did:key:z6Mkon22vwz9JoNpGDxCrGZRgeNFTdRTwXYYN3fvAhA3K19x"}

func (env *statusEnv) evidence(c *IDStatusClient) *IDChainEvidence {
	if c == nil {
		c = env.client
	}
	return c.IDChainEvidence(context.Background(), env.bundle("alice", "coordinator"), statusSubject, "example.com")
}

func (env *statusEnv) verdict(e *IDChainEvidence) IDChainResult {
	return VerifyIDChain(env.bundle("alice", "coordinator"), statusSubject, e, "example.com")
}

func ageOf(e *IDChainEvidence) any {
	if e.AgeSeconds == nil {
		return nil
	}
	return *e.AgeSeconds
}

func TestStatusClientAFirstReadObservesStatusAndAuthorityTogether(t *testing.T) {
	env := newStatusEnv(t)
	e := env.evidence(nil)
	want := map[string]any{"domain": "example.com", "dns_name": "_awid.example.com", "inherited": false, "controller_key": env.ctrl["example.com"]}
	if !reflect.DeepEqual(e.NamespaceAuthority, want) || ageOf(e) != 0.0 || e.RefreshFailed {
		t.Fatalf("evidence %+v", e)
	}
	if got := env.verdict(e); got.Reason != "verified" {
		t.Fatalf("verdict %+v", got)
	}
	if r, d := env.counts(); r != 1 || d != 1 {
		t.Fatalf("requests=%d dns=%d", r, d)
	}
}

func TestStatusClientEvidenceIsReusedThrough60SecondsWithoutDNSOrHTTP(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(60)
	e := env.evidence(nil)
	if ageOf(e) != 60.0 || e.RefreshFailed {
		t.Fatalf("evidence age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
	if r, d := env.counts(); r != 1 || d != 1 {
		t.Fatalf("a fresh hit did network work: requests=%d dns=%d", r, d)
	}
}

func TestStatusClientAfter60SecondsTheCallerAwaitsARefresh(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(61)
	env.set(func() { env.status["example.com"] = env.v.Statuses["alice-revoked-now"] })
	e := env.evidence(nil)
	if !reflect.DeepEqual(e.Status, env.v.Statuses["alice-revoked-now"]) || ageOf(e) != 0.0 || e.RefreshFailed {
		t.Fatalf("evidence age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
	if r, d := env.counts(); r != 2 || d != 2 {
		t.Fatalf("requests=%d dns=%d", r, d)
	}
}

func TestStatusClientStaleEvidenceIsNeverPresentedWithoutAFailedRefresh(t *testing.T) {
	for _, name := range []string{"cached-status-age-61-without-failed-refresh", "cached-status-age-901-without-failed-refresh"} {
		t.Run(name, func(t *testing.T) {
			env := newStatusEnv(t)
			var age float64
			var expected IDChainResult
			for _, c := range env.v.Cases {
				if c.Name == name {
					age, expected = c.Cache.Age, c.Expected
					if c.Cache.Refresh != "not_needed" {
						t.Fatalf("case %s refresh=%s", name, c.Cache.Refresh)
					}
				}
			}
			stale := &IDChainEvidence{Status: env.status["example.com"], NamespaceAuthority: map[string]any{"domain": "example.com", "dns_name": "_awid.example.com", "inherited": false, "controller_key": env.ctrl["example.com"]}, AgeSeconds: &age}
			if got := env.verdict(stale); !reflect.DeepEqual(got, expected) {
				t.Fatalf("frozen verdict %+v want %+v", got, expected)
			}
			env.evidence(nil)
			env.clock.Add(int64(age))
			refreshed := env.evidence(nil)
			if ageOf(refreshed) != 0.0 || refreshed.RefreshFailed || env.verdict(refreshed).Reason != "verified" {
				t.Fatalf("refreshed age=%v failed=%v", ageOf(refreshed), refreshed.RefreshFailed)
			}
			env.clock.Add(int64(age))
			env.set(func() { env.httpStatus = 503 })
			failed := env.evidence(nil)
			if ageOf(failed) != age || !failed.RefreshFailed || reflect.DeepEqual(env.verdict(failed), expected) {
				t.Fatalf("failed age=%v failed=%v", ageOf(failed), failed.RefreshFailed)
			}
		})
	}
}

func TestStatusClientAFailedRefreshReusesLastKnownGoodEvidenceThrough900Seconds(t *testing.T) {
	for _, tc := range []struct {
		age    int64
		reason string
	}{{61, "verified"}, {900, "verified"}, {901, "status_expired"}} {
		for _, failure := range []string{"http-500", "http-429", "dns", "timeout"} {
			t.Run(fmt.Sprintf("%d/%s", tc.age, failure), func(t *testing.T) {
				env := newStatusEnv(t)
				first := env.evidence(nil)
				env.clock.Add(tc.age)
				client := env.client
				switch failure {
				case "http-500":
					env.set(func() { env.httpStatus = 500 })
				case "http-429":
					env.set(func() { env.httpStatus = 429 })
				case "dns":
					env.set(func() { env.dnsFailure = true })
				case "timeout":
					client.Timeout = 50 * time.Millisecond
					env.set(func() { env.httpDelay = time.Second })
				}
				e := env.evidence(client)
				if !reflect.DeepEqual(e.Status, first.Status) || !reflect.DeepEqual(e.NamespaceAuthority, first.NamespaceAuthority) || ageOf(e) != float64(tc.age) || !e.RefreshFailed {
					t.Fatalf("evidence age=%v failed=%v", ageOf(e), e.RefreshFailed)
				}
				if got := env.verdict(e).Reason; got != tc.reason {
					t.Fatalf("verdict %s want %s", got, tc.reason)
				}
				// A failed attempt never restarts the grace.
				env.clock.Add(1)
				again := env.evidence(client)
				if ageOf(again) != float64(tc.age+1) {
					t.Fatalf("grace restarted: age=%v", ageOf(again))
				}
			})
		}
	}
}

func TestStatusClientLastKnownGoodIsAgedThroughTheFailedAttempt(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(61)
	env.set(func() { env.httpStatus = 503; env.advanceDuringFetch = 5 })
	e := env.evidence(nil)
	if ageOf(e) != 66.0 || !e.RefreshFailed {
		t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
}

func TestStatusClientAFailedFirstReadHasNoEvidence(t *testing.T) {
	env := newStatusEnv(t)
	env.set(func() { env.httpStatus = 429 })
	e := env.evidence(nil)
	if e.AgeSeconds != nil || !e.RefreshFailed || env.verdict(e).Reason != "evidence_unavailable" {
		t.Fatalf("evidence age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
}

func TestStatusClientAFailedAttemptSuppressesAttemptsFor60Seconds(t *testing.T) {
	env := newStatusEnv(t)
	env.set(func() { env.httpStatus = 503 })
	for _, elapsed := range []int64{0, 1, 60} {
		env.clock.Store(1_000_000 + elapsed)
		e := env.evidence(nil)
		if r, d := env.counts(); e.AgeSeconds != nil || !e.RefreshFailed || r != 1 || d != 1 {
			t.Fatalf("at %d: age=%v failed=%v requests=%d dns=%d", elapsed, ageOf(e), e.RefreshFailed, r, d)
		}
	}
	env.clock.Add(1)
	env.evidence(nil)
	if r, _ := env.counts(); r != 2 {
		t.Fatalf("no attempt after the cooldown: requests=%d", r)
	}
}

func TestStatusClientDuringACooldownLastKnownGoodEvidenceKeepsItsTrueAge(t *testing.T) {
	env := newStatusEnv(t)
	first := env.evidence(nil)
	env.clock.Add(61)
	env.set(func() { env.httpStatus = 503 })
	if e := env.evidence(nil); ageOf(e) != 61.0 {
		t.Fatalf("age=%v", ageOf(e))
	}
	env.clock.Add(9)
	e := env.evidence(nil)
	if !reflect.DeepEqual(e.Status, first.Status) || ageOf(e) != 70.0 || !e.RefreshFailed || env.verdict(e).Reason != "verified" {
		t.Fatalf("age=%v failed=%v verdict=%s", ageOf(e), e.RefreshFailed, env.verdict(e).Reason)
	}
	if r, _ := env.counts(); r != 2 {
		t.Fatalf("requests=%d", r)
	}
}

func TestStatusClientACooldownNeverExtendsTheGrace(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(850)
	env.set(func() { env.httpStatus = 503 })
	if e := env.evidence(nil); env.verdict(e).Reason != "verified" {
		t.Fatalf("verdict=%s", env.verdict(e).Reason)
	}
	env.clock.Add(51)
	e := env.evidence(nil)
	if ageOf(e) != 901.0 || !e.RefreshFailed || env.verdict(e).Reason != "status_expired" {
		t.Fatalf("age=%v failed=%v verdict=%s", ageOf(e), e.RefreshFailed, env.verdict(e).Reason)
	}
	if r, _ := env.counts(); r != 2 {
		t.Fatalf("requests=%d", r)
	}
}

var statusGlobalSubject = IDChainSubject{ID: "did:aw:44aKNQyvo1xh8rv6TfdfzjTn6nRp", DIDKey: "did:key:z6MkwVDfCg9LbbY6xjH3EZk8YSFQZujV5Y4y1ZWeER9tDiN3"}

func TestStatusClientASuccessEndsTheDomainsCooldown(t *testing.T) {
	env := newStatusEnv(t)
	gate := make(chan struct{})
	env.set(func() { env.gate["example.com"] = gate })
	succeeding := make(chan *IDChainEvidence)
	go func() { succeeding <- env.evidence(nil) }()
	for r, _ := env.counts(); r != 1; r, _ = env.counts() {
		time.Sleep(time.Millisecond)
	}
	env.set(func() { env.dnsFailure = true })
	if failed := env.client.IDChainEvidence(context.Background(), nil, statusGlobalSubject, "example.com"); !failed.RefreshFailed {
		t.Fatal("the failing attempt was not reported as failed")
	}
	env.set(func() { env.dnsFailure = false })
	close(gate)
	if e := <-succeeding; ageOf(e) != 0.0 {
		t.Fatalf("succeeding age=%v", ageOf(e))
	}
	env.set(func() { delete(env.gate, "example.com") })
	retried := env.client.IDChainEvidence(context.Background(), nil, statusGlobalSubject, "example.com")
	if ageOf(retried) != 0.0 || retried.RefreshFailed {
		t.Fatalf("retried age=%v failed=%v", ageOf(retried), retried.RefreshFailed)
	}
	if r, _ := env.counts(); r != 2 {
		t.Fatalf("requests=%d", r)
	}
}

func TestStatusClientACooldownIsPerDomainAndNotPersisted(t *testing.T) {
	env := newStatusEnv(t)
	other := map[string]any{}
	for k, v := range env.status["example.com"] {
		other[k] = v
	}
	other["domain"] = "other.example"
	env.set(func() {
		env.status["other.example"] = other
		env.ctrl["other.example"] = env.ctrl["example.com"]
		env.httpStatus = 503
	})
	env.evidence(nil)
	env.set(func() { env.httpStatus = 200 })
	if e := env.client.IDChainEvidence(context.Background(), nil, statusGlobalSubject, "other.example"); ageOf(e) != 0.0 {
		t.Fatalf("another domain was suppressed: age=%v", ageOf(e))
	}
	if e := env.evidence(nil); !e.RefreshFailed {
		t.Fatal("the failed domain's cooldown did not hold")
	}
	if r, _ := env.counts(); r != 2 {
		t.Fatalf("requests=%d", r)
	}
	if e := env.evidence(env.makeClient(5 * time.Second)); ageOf(e) != 0.0 || e.RefreshFailed {
		t.Fatalf("a new client inherited the cooldown: age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
	if r, _ := env.counts(); r != 3 {
		t.Fatalf("requests=%d", r)
	}
}

func TestStatusClientConcurrentStaleReadersShareOneRefresh(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(61)
	gate := make(chan struct{})
	env.set(func() { env.gate["example.com"] = gate })
	results := concurrently(10, func() *IDChainEvidence { return env.evidence(nil) }, func() bool { r, _ := env.counts(); return r == 2 }, gate)
	for _, e := range results {
		if ageOf(e) != 0.0 || e.RefreshFailed {
			t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
		}
	}
	if r, d := env.counts(); r != 2 || d != 2 {
		t.Fatalf("requests=%d dns=%d", r, d)
	}
}

func TestStatusClientConcurrentReadersShareOneFailedAttempt(t *testing.T) {
	env := newStatusEnv(t)
	gate := make(chan struct{})
	env.set(func() { env.gate["example.com"] = gate; env.httpStatus = 503 })
	results := concurrently(10, func() *IDChainEvidence { return env.evidence(nil) }, func() bool { r, _ := env.counts(); return r == 1 }, gate)
	for _, e := range results {
		if e.AgeSeconds != nil || !e.RefreshFailed {
			t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
		}
	}
	if r, _ := env.counts(); r != 1 {
		t.Fatalf("requests=%d", r)
	}
}

func concurrently(n int, read func() *IDChainEvidence, started func() bool, gate chan struct{}) []*IDChainEvidence {
	results := make([]*IDChainEvidence, n)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = read() }(i)
	}
	for deadline := time.Now().Add(2 * time.Second); !started() && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	return results
}

func TestStatusClientACancelledReaderDoesNotCancelTheSharedRefresh(t *testing.T) {
	env := newStatusEnv(t)
	gate := make(chan struct{})
	env.set(func() { env.gate["example.com"] = gate })
	ctx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan *IDChainEvidence)
	go func() {
		cancelled <- env.client.IDChainEvidence(ctx, env.bundle("alice", "coordinator"), statusSubject, "example.com")
	}()
	for r, _ := env.counts(); r == 0; r, _ = env.counts() {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if e := <-cancelled; e.AgeSeconds != nil {
		t.Fatalf("a cancelled reader got evidence age=%v", ageOf(e))
	}
	done := make(chan *IDChainEvidence)
	go func() { done <- env.evidence(nil) }()
	time.Sleep(20 * time.Millisecond)
	close(gate)
	e := <-done
	if ageOf(e) != 0.0 || e.RefreshFailed {
		t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
	if r, _ := env.counts(); r != 1 {
		t.Fatalf("the shared refresh was restarted: requests=%d", r)
	}
}

func TestStatusClientOneTimeoutBoundsDNSAndHTTPTogether(t *testing.T) {
	env := newStatusEnv(t)
	client := env.makeClient(150 * time.Millisecond)
	env.set(func() { env.dnsDelay = 100 * time.Millisecond; env.httpDelay = 100 * time.Millisecond })
	started := time.Now()
	e := env.evidence(client)
	if e.AgeSeconds != nil || !e.RefreshFailed {
		t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the attempt took %v", elapsed)
	}
}

func TestStatusClientAStalledDomainDoesNotDelayAnotherDomain(t *testing.T) {
	env := newStatusEnv(t)
	other := map[string]any{}
	for k, v := range env.status["example.com"] {
		other[k] = v
	}
	other["domain"] = "other.example"
	gate := make(chan struct{})
	defer close(gate)
	env.set(func() {
		env.status["other.example"] = other
		env.ctrl["other.example"] = env.ctrl["example.com"]
		env.gate["other.example"] = gate
	})
	go env.client.IDChainEvidence(context.Background(), nil, statusGlobalSubject, "other.example")
	for r, _ := env.counts(); r == 0; r, _ = env.counts() {
		time.Sleep(time.Millisecond)
	}
	done := make(chan *IDChainEvidence)
	go func() { done <- env.evidence(nil) }()
	select {
	case e := <-done:
		if ageOf(e) != 0.0 || e.RefreshFailed {
			t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
		}
	case <-time.After(time.Second):
		t.Fatal("a stalled domain delayed another domain")
	}
}

func TestStatusClientTheObservationTimeIsWhenTheRefreshBegan(t *testing.T) {
	env := newStatusEnv(t)
	env.set(func() { env.advanceDuringFetch = 7 })
	first := env.evidence(nil)
	if ageOf(first) != 7.0 {
		t.Fatalf("returned age=%v", ageOf(first))
	}
	env.set(func() { env.advanceDuringFetch = 0 })
	env.clock.Add(53)
	if e := env.evidence(nil); ageOf(e) != 60.0 {
		t.Fatalf("stored age=%v", ageOf(e))
	}
}

func TestStatusClientAnEntryStampedAheadOfTheClockIsRefreshed(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(-10)
	e := env.evidence(nil)
	if ageOf(e) != 0.0 || e.RefreshFailed {
		t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
	if r, _ := env.counts(); r != 2 {
		t.Fatalf("requests=%d", r)
	}
}

func TestStatusClientAnEntryStampedAheadOfTheClockGivesNoGrace(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(-10)
	env.set(func() { env.httpStatus = 503 })
	e := env.evidence(nil)
	if e.AgeSeconds != nil || !e.RefreshFailed {
		t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
}

func TestStatusClientAClockSteppingBackDuringARefreshLeavesItsEvidenceUnavailable(t *testing.T) {
	env := newStatusEnv(t)
	env.set(func() { env.advanceDuringFetch = -3 })
	e := env.evidence(nil)
	if ageOf(e) != -3.0 || env.verdict(e).Reason != "evidence_unavailable" {
		t.Fatalf("age=%v verdict=%s", ageOf(e), env.verdict(e).Reason)
	}
}

func TestStatusClientACooldownRecordedAheadOfThisClockDoesNotSuppressAttempts(t *testing.T) {
	env := newStatusEnv(t)
	env.set(func() { env.httpStatus = 503 })
	env.evidence(nil)
	env.clock.Add(-5)
	env.set(func() { env.httpStatus = 200 })
	if e := env.evidence(nil); ageOf(e) != 0.0 || e.RefreshFailed {
		t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
}

func TestStatusClientAnUnreadableRefusalIsAFailedRefresh(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(61)
	env.set(func() { env.httpStatus = 502; env.rawBody = []byte("\xff not json") })
	e := env.evidence(nil)
	if ageOf(e) != 61.0 || !e.RefreshFailed {
		t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
}

func TestStatusClientASuccessfulAnswerReplacesPriorEvidenceEvenThroughALaterOutage(t *testing.T) {
	for _, fixture := range []string{"alice-revoked-now", "root-replaced"} {
		t.Run(fixture, func(t *testing.T) {
			env := newStatusEnv(t)
			env.evidence(nil)
			env.clock.Add(61)
			env.set(func() {
				env.status["example.com"] = env.v.Statuses[fixture]
				env.ctrl["example.com"] = openEpochKey(env.v.Statuses[fixture])
			})
			env.evidence(nil)
			env.clock.Add(61)
			env.set(func() { env.httpStatus = 503 })
			e := env.evidence(nil)
			if !reflect.DeepEqual(e.Status, env.v.Statuses[fixture]) || ageOf(e) != 61.0 || !e.RefreshFailed {
				t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
			}
		})
	}
}

func TestStatusClientContradictoryAuthorityIsKeptAsCurrentAndNeverVerifies(t *testing.T) {
	env := newStatusEnv(t)
	env.evidence(nil)
	env.clock.Add(61)
	env.set(func() { env.ctrl["example.com"] = "did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2" })
	e := env.evidence(nil)
	if e.NamespaceAuthority["controller_key"] != "did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2" || env.verdict(e).Reason != "evidence_unavailable" {
		t.Fatalf("authority=%v verdict=%s", e.NamespaceAuthority, env.verdict(e).Reason)
	}
	env.clock.Add(61)
	env.set(func() { env.httpStatus = 503 })
	if e := env.evidence(nil); env.verdict(e).Reason != "evidence_unavailable" {
		t.Fatalf("an outage restored the older tree: %s", env.verdict(e).Reason)
	}
}

func TestStatusClientAMalformedSuccessfulAnswerIsUnavailableAndEndsTheOldTree(t *testing.T) {
	oversized := `{"x":"` + strings.Repeat("a", MaxResponseSize) + `"}`
	for name, body := range map[string]string{"array": "[]", "not json": "not json", "string": `"text"`, "null": "null", "trailing value": `{"v":1} []`, "oversized": oversized, "read error": ""} {
		t.Run(name, func(t *testing.T) {
			env := newStatusEnv(t)
			env.evidence(nil)
			env.clock.Add(61)
			env.set(func() {
				env.rawBody = []byte(body)
				env.brokenBody = name == "read error"
			})
			e := env.evidence(nil)
			if e.AgeSeconds != nil || e.RefreshFailed {
				t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
			}
			env.set(func() { env.rawBody = nil; env.brokenBody = false; env.httpStatus = 503 })
			env.clock.Add(1)
			if e := env.evidence(nil); e.AgeSeconds != nil {
				t.Fatalf("the old tree outlived a malformed answer: age=%v", ageOf(e))
			}
		})
	}
}

func TestStatusClientAChainlessLocalSubjectCreatesNoRegistryDependency(t *testing.T) {
	env := newStatusEnv(t)
	e := env.client.IDChainEvidence(context.Background(), nil, statusSubject, "example.com")
	if e.AgeSeconds != nil || e.RefreshFailed {
		t.Fatalf("age=%v failed=%v", ageOf(e), e.RefreshFailed)
	}
	if r, d := env.counts(); r != 0 || d != 0 {
		t.Fatalf("requests=%d dns=%d", r, d)
	}
}

func TestStatusClientABundleForAnotherDomainCreatesNoRegistryDependency(t *testing.T) {
	env := newStatusEnv(t)
	env.client.IDChainEvidence(context.Background(), env.bundle("alice", "coordinator"), statusSubject, "other.example")
	if r, d := env.counts(); r != 0 || d != 0 {
		t.Fatalf("requests=%d dns=%d", r, d)
	}
}

func TestStatusClientTheRawStatusFetchErrorsOnARateLimitedAnswer(t *testing.T) {
	env := newStatusEnv(t)
	env.set(func() { env.httpStatus = 429 })
	request, err := IDStatusRequest(env.bundle("alice", "coordinator"), statusSubject, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	status, err := env.client.FetchIDCertificateStatus(context.Background(), "example.com", request)
	var registryErr *RegistryError
	if status != nil || !errors.As(err, &registryErr) || registryErr.StatusCode != 429 {
		t.Fatalf("status=%v err=%v", status, err)
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Fatal("empty error")
	}
}
