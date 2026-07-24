package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type rotationRegistryFixture struct {
	t                  *testing.T
	server             *httptest.Server
	didAW              string
	oldDID             string
	mu                 sync.Mutex
	currentDID         string
	resolveUnavailable bool
	putCalls           int
	requests           []string
	onPut              func(*rotationRegistryFixture, http.ResponseWriter, *http.Request, didUpdateRequest)
}

func newRotationRegistryFixture(
	t *testing.T,
	didAW string,
	oldDID string,
	onPut func(*rotationRegistryFixture, http.ResponseWriter, *http.Request, didUpdateRequest),
) *rotationRegistryFixture {
	t.Helper()
	fixture := &rotationRegistryFixture{t: t, didAW: didAW, oldDID: oldDID, currentDID: oldDID, onPut: onPut}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.handle))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *rotationRegistryFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+f.didAW+"/full":
		f.requests = append(f.requests, "GET full")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did_aw":          f.didAW,
			"current_did_key": f.currentDID,
			"created_at":      "2026-07-24T00:00:00Z",
			"updated_at":      "2026-07-24T00:00:00Z",
		})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+f.didAW+"/key":
		f.requests = append(f.requests, "GET key")
		if f.resolveUnavailable {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did_aw":          f.didAW,
			"current_did_key": f.currentDID,
			"log_head": map[string]any{
				"seq":             1,
				"operation":       "register_did",
				"new_did_key":     f.oldDID,
				"entry_hash":      strings.Repeat("a", 64),
				"state_hash":      strings.Repeat("b", 64),
				"authorized_by":   f.oldDID,
				"signature":       "test",
				"timestamp":       "2026-07-24T00:00:00Z",
				"prev_entry_hash": nil,
			},
		})
	case r.Method == http.MethodPut && r.URL.Path == "/v1/did/"+f.didAW:
		f.putCalls++
		f.requests = append(f.requests, "PUT")
		var request didUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Error(err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f.onPut(f, w, r, request)
	default:
		f.t.Errorf("unexpected registry request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *rotationRegistryFixture) dropResponse(w http.ResponseWriter) {
	connection, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		f.t.Error(err)
		return
	}
	_ = connection.Close()
}

func (f *rotationRegistryFixture) snapshot() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.putCalls, append([]string(nil), f.requests...)
}

func newRotationTestKeys(t *testing.T) (string, ed25519.PrivateKey, string, ed25519.PrivateKey, string) {
	t.Helper()
	oldPublic, oldPrivate, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, newPrivate, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPublic)
	newDID := ComputeDIDKey(newPrivate.Public().(ed25519.PublicKey))
	return oldDID, oldPrivate, newDID, newPrivate, ComputeStableID(oldPublic)
}

func TestRegistryClientReconcilesAppliedRotationAfterResponseDrop(t *testing.T) {
	oldDID, oldPrivate, newDID, newPrivate, didAW := newRotationTestKeys(t)
	fixture := newRotationRegistryFixture(t, didAW, oldDID, func(f *rotationRegistryFixture, w http.ResponseWriter, _ *http.Request, request didUpdateRequest) {
		if f.putCalls == 1 {
			f.currentDID = request.NewDIDKey
			f.dropResponse(w)
			return
		}
		http.Error(w, "rotation sequence conflict", http.StatusConflict)
	})

	client := NewAWIDRegistryClient(fixture.server.Client(), nil)
	mapping, err := client.RotateDIDKey(context.Background(), fixture.server.URL, didAW, oldPrivate, newPrivate)
	if err != nil {
		t.Fatalf("RotateDIDKey after committed response drop: %v", err)
	}
	if mapping == nil || mapping.DIDAW != didAW || mapping.CurrentDIDKey != newDID {
		t.Fatalf("mapping=%+v, want did_aw=%q current_did_key=%q", mapping, didAW, newDID)
	}
	putCalls, _ := fixture.snapshot()
	if putCalls != 1 {
		t.Fatalf("rotation PUT calls=%d, want 1 (reconcile instead of replay)", putCalls)
	}
}

func TestRegistryClientRetriesRotationOnlyAfterConfirmingFirstAttemptDidNotApply(t *testing.T) {
	oldDID, oldPrivate, newDID, newPrivate, didAW := newRotationTestKeys(t)
	fixture := newRotationRegistryFixture(t, didAW, oldDID, func(f *rotationRegistryFixture, w http.ResponseWriter, _ *http.Request, request didUpdateRequest) {
		if f.putCalls == 1 {
			f.dropResponse(w)
			return
		}
		f.currentDID = request.NewDIDKey
		_ = json.NewEncoder(w).Encode(map[string]any{"updated": true})
	})

	client := NewAWIDRegistryClient(fixture.server.Client(), nil)
	mapping, err := client.RotateDIDKey(context.Background(), fixture.server.URL, didAW, oldPrivate, newPrivate)
	if err != nil {
		t.Fatalf("RotateDIDKey before-apply response drop: %v", err)
	}
	if mapping == nil || mapping.CurrentDIDKey != newDID {
		t.Fatalf("mapping=%+v, want current_did_key=%q", mapping, newDID)
	}
	putCalls, requests := fixture.snapshot()
	if putCalls != 2 {
		t.Fatalf("rotation PUT calls=%d, want 2", putCalls)
	}
	if got := strings.Join(requests, ","); got != "GET full,GET key,PUT,GET key,PUT" {
		t.Fatalf("request order=%s; retry must follow authoritative reconciliation", got)
	}
}

func TestRegistryClientKeepsOutcomeUnknownWhenRetryCannotResolveFirstAmbiguousAttempt(t *testing.T) {
	oldDID, oldPrivate, _, newPrivate, didAW := newRotationTestKeys(t)
	fixture := newRotationRegistryFixture(t, didAW, oldDID, func(f *rotationRegistryFixture, w http.ResponseWriter, _ *http.Request, _ didUpdateRequest) {
		if f.putCalls == 1 {
			f.dropResponse(w)
			return
		}
		http.Error(w, "rotation rejected", http.StatusConflict)
	})

	client := NewAWIDRegistryClient(fixture.server.Client(), nil)
	_, err := client.RotateDIDKey(context.Background(), fixture.server.URL, didAW, oldPrivate, newPrivate)
	var outcomeErr *DIDRotationError
	if !errors.As(err, &outcomeErr) || outcomeErr.Outcome != DIDRotationOutcomeUnknown {
		t.Fatalf("error=%v, want outcome-unknown DIDRotationError", err)
	}
}

func TestRegistryClientAcceptsExactRotationReplayWhenRegistryHasReplacementKey(t *testing.T) {
	oldDID, oldPrivate, newDID, newPrivate, didAW := newRotationTestKeys(t)
	fixture := newRotationRegistryFixture(t, didAW, oldDID, func(f *rotationRegistryFixture, w http.ResponseWriter, _ *http.Request, request didUpdateRequest) {
		f.currentDID = request.NewDIDKey
		http.Error(w, "rotation entry already applied", http.StatusConflict)
	})

	client := NewAWIDRegistryClient(fixture.server.Client(), nil)
	mapping, err := client.RotateDIDKey(context.Background(), fixture.server.URL, didAW, oldPrivate, newPrivate)
	if err != nil {
		t.Fatalf("RotateDIDKey exact replay: %v", err)
	}
	if mapping == nil || mapping.CurrentDIDKey != newDID {
		t.Fatalf("mapping=%+v, want current_did_key=%q", mapping, newDID)
	}
}

func TestRegistryClientReportsRotationDefinitelyNotAppliedWhenRegistryRemainsOld(t *testing.T) {
	oldDID, oldPrivate, _, newPrivate, didAW := newRotationTestKeys(t)
	fixture := newRotationRegistryFixture(t, didAW, oldDID, func(_ *rotationRegistryFixture, w http.ResponseWriter, _ *http.Request, _ didUpdateRequest) {
		http.Error(w, "rotation rejected", http.StatusConflict)
	})

	client := NewAWIDRegistryClient(fixture.server.Client(), nil)
	_, err := client.RotateDIDKey(context.Background(), fixture.server.URL, didAW, oldPrivate, newPrivate)
	var outcomeErr *DIDRotationError
	if !errors.As(err, &outcomeErr) || outcomeErr.Outcome != DIDRotationDefinitelyNotApplied {
		t.Fatalf("error=%v, want definitely-not-applied DIDRotationError", err)
	}
}

func TestRegistryClientReportsRotationOutcomeUnknownWhenCurrentStateCannotBeResolved(t *testing.T) {
	oldDID, oldPrivate, _, newPrivate, didAW := newRotationTestKeys(t)
	fixture := newRotationRegistryFixture(t, didAW, oldDID, func(f *rotationRegistryFixture, w http.ResponseWriter, _ *http.Request, _ didUpdateRequest) {
		f.resolveUnavailable = true
		f.dropResponse(w)
	})

	client := NewAWIDRegistryClient(fixture.server.Client(), nil)
	_, err := client.RotateDIDKey(context.Background(), fixture.server.URL, didAW, oldPrivate, newPrivate)
	var outcomeErr *DIDRotationError
	if !errors.As(err, &outcomeErr) || outcomeErr.Outcome != DIDRotationOutcomeUnknown {
		t.Fatalf("error=%v, want outcome-unknown DIDRotationError", err)
	}
}

func TestRegistryClientReportsRotationOutcomeUnknownForUnexpectedCurrentKey(t *testing.T) {
	oldDID, oldPrivate, _, newPrivate, didAW := newRotationTestKeys(t)
	thirdPublic, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	thirdDID := ComputeDIDKey(thirdPublic)
	fixture := newRotationRegistryFixture(t, didAW, oldDID, func(f *rotationRegistryFixture, w http.ResponseWriter, _ *http.Request, _ didUpdateRequest) {
		f.currentDID = thirdDID
		f.dropResponse(w)
	})

	client := NewAWIDRegistryClient(fixture.server.Client(), nil)
	_, err = client.RotateDIDKey(context.Background(), fixture.server.URL, didAW, oldPrivate, newPrivate)
	var outcomeErr *DIDRotationError
	if !errors.As(err, &outcomeErr) || outcomeErr.Outcome != DIDRotationOutcomeUnknown {
		t.Fatalf("error=%v, want outcome-unknown DIDRotationError", err)
	}
}
