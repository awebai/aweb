package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// registryRefetchVectorPath is the shared vector for docs/trust-model.md's
// bounded refetch: Go and channel-core both run it.
const registryRefetchVectorPath = "../../../test-vectors/trust/registry-refetch-v1.json"

type registryRefetchResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

type registryRefetchStep struct {
	AdvanceSeconds int    `json:"advance_seconds"`
	FromDID        string `json:"from_did"`
	ExpectedStatus string `json:"expected_status"`
}

type registryRefetchCase struct {
	Name             string                               `json:"name"`
	Address          string                               `json:"address"`
	FromStableID     string                               `json:"from_stable_id"`
	Responses        map[string][]registryRefetchResponse `json:"responses"`
	Steps            []registryRefetchStep                `json:"steps"`
	ExpectedRequests map[string]int                       `json:"expected_requests"`
}

type registryRefetchVector struct {
	Schema                 string                `json:"schema"`
	Description            string                `json:"description"`
	StartTime              string                `json:"start_time"`
	RefetchIntervalSeconds int                   `json:"refetch_interval_seconds"`
	Vectors                []registryRefetchCase `json:"vectors"`
}

func seededKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func rawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// buildRegistryRefetchVector builds the vector from fixed seeds and times, so
// the frozen file can be checked against it.
func buildRegistryRefetchVector(t *testing.T) registryRefetchVector {
	t.Helper()
	oldKey, newKey, otherKey := seededKey(1), seededKey(2), seededKey(3)
	oldDID := ComputeDIDKey(oldKey.Public().(ed25519.PublicKey))
	newDID := ComputeDIDKey(newKey.Public().(ed25519.PublicKey))
	stableID := ComputeStableID(oldKey.Public().(ed25519.PublicKey))
	otherStableID := ComputeStableID(otherKey.Public().(ed25519.PublicKey))

	create := signedDidKeyResolution(t, oldKey, &DidKeyResolution{
		DIDAW: stableID, CurrentDIDKey: oldDID,
		LogHead: &DidKeyEvidence{Seq: 1, Operation: "create", NewDIDKey: oldDID, AuthorizedBy: oldDID, Timestamp: "2026-11-01T00:00:00Z"},
	}).LogHead
	prev := create.EntryHash
	rotate := signedDidKeyResolution(t, oldKey, &DidKeyResolution{
		DIDAW: stableID, CurrentDIDKey: newDID,
		LogHead: &DidKeyEvidence{Seq: 2, Operation: "rotate_key", PreviousDIDKey: &oldDID, NewDIDKey: newDID, PrevEntryHash: &prev, AuthorizedBy: oldDID, Timestamp: "2026-11-02T00:00:00Z"},
	}).LogHead

	address := func(didAW, currentDIDKey string) registryRefetchResponse {
		return registryRefetchResponse{Status: 200, Body: rawJSON(t, map[string]any{
			"address_id": "addr-alice", "domain": "acme.com", "name": "alice",
			"did_aw": didAW, "current_did_key": currentDIDKey, "created_at": "2026-11-01T00:00:00Z",
		})}
	}
	key := func(currentDIDKey string, head *DidKeyEvidence) registryRefetchResponse {
		return registryRefetchResponse{Status: 200, Body: rawJSON(t, map[string]any{"did_aw": stableID, "current_did_key": currentDIDKey, "log_head": head})}
	}
	unavailable := registryRefetchResponse{Status: 503}
	addressPath := "/v1/namespaces/acme.com/addresses/alice"
	keyPath := "/v1/did/" + stableID + "/key"
	logPath := "/v1/did/" + stableID + "/log"
	log := registryRefetchResponse{Status: 200, Body: rawJSON(t, []DidKeyEvidence{*create})}

	return registryRefetchVector{
		Schema:                 "aweb.trust.registry-refetch.v1",
		Description:            "Bounded registry refetch (docs/trust-model.md, 'A cached registry answer is not the registry's answer'): a cached address binding or current key that disagrees with the signed message is read again from the registry once, and the fresh answer decides; at most one forced read per sender per refetch_interval_seconds. Responses are served in order per path, the last one repeating; steps run in order on one client, advancing its clock. expected_requests counts the address and key reads the bound limits; log reads are not counted, since clients may verify a genesis head without one.",
		StartTime:              "2026-11-18T00:00:00Z",
		RefetchIntervalSeconds: 30,
		Vectors: []registryRefetchCase{
			{
				Name: "key-rotated-after-it-was-cached-is-read-again-and-verifies", Address: "acme.com/alice", FromStableID: stableID,
				Responses: map[string][]registryRefetchResponse{addressPath: {address(stableID, oldDID)}, keyPath: {key(oldDID, create), key(newDID, rotate)}, logPath: {log}},
				Steps: []registryRefetchStep{
					{FromDID: oldDID, ExpectedStatus: "verified"},
					{FromDID: newDID, ExpectedStatus: "verified"},
				},
				ExpectedRequests: map[string]int{addressPath: 1, keyPath: 2},
			},
			{
				Name: "key-read-again-and-unchanged-is-a-mismatch-without-another-read-in-the-interval", Address: "acme.com/alice", FromStableID: stableID,
				Responses: map[string][]registryRefetchResponse{addressPath: {address(stableID, oldDID)}, keyPath: {key(oldDID, create)}, logPath: {log}},
				Steps: []registryRefetchStep{
					{FromDID: oldDID, ExpectedStatus: "verified"},
					{FromDID: newDID, ExpectedStatus: "identity_mismatch"},
					{AdvanceSeconds: 10, FromDID: newDID, ExpectedStatus: "identity_mismatch"},
				},
				ExpectedRequests: map[string]int{addressPath: 1, keyPath: 2},
			},
			{
				Name: "key-read-that-fails-is-stale-until-the-interval-ends", Address: "acme.com/alice", FromStableID: stableID,
				Responses: map[string][]registryRefetchResponse{addressPath: {address(stableID, oldDID)}, keyPath: {key(oldDID, create), unavailable}, logPath: {log}},
				Steps: []registryRefetchStep{
					{FromDID: oldDID, ExpectedStatus: "verified"},
					{FromDID: newDID, ExpectedStatus: "verification_stale"},
					{AdvanceSeconds: 10, FromDID: newDID, ExpectedStatus: "verification_stale"},
					{AdvanceSeconds: 30, FromDID: newDID, ExpectedStatus: "verification_stale"},
				},
				ExpectedRequests: map[string]int{addressPath: 1, keyPath: 3},
			},
			{
				Name: "address-cached-for-another-identity-is-read-again-and-verifies", Address: "acme.com/alice", FromStableID: stableID,
				Responses: map[string][]registryRefetchResponse{addressPath: {address(otherStableID, oldDID), address(stableID, oldDID)}, keyPath: {key(oldDID, create)}, logPath: {log}},
				Steps: []registryRefetchStep{
					{FromDID: oldDID, ExpectedStatus: "verified"},
				},
				ExpectedRequests: map[string]int{addressPath: 2, keyPath: 1},
			},
			{
				Name: "address-read-again-for-another-identity-is-a-mismatch-without-another-read-in-the-interval", Address: "acme.com/alice", FromStableID: stableID,
				Responses: map[string][]registryRefetchResponse{addressPath: {address(otherStableID, oldDID)}},
				Steps: []registryRefetchStep{
					{FromDID: oldDID, ExpectedStatus: "identity_mismatch"},
					{AdvanceSeconds: 10, FromDID: oldDID, ExpectedStatus: "identity_mismatch"},
				},
				ExpectedRequests: map[string]int{addressPath: 2, keyPath: 0},
			},
			{
				Name: "address-read-that-fails-is-stale", Address: "acme.com/alice", FromStableID: stableID,
				Responses: map[string][]registryRefetchResponse{addressPath: {address(otherStableID, oldDID), unavailable}},
				Steps: []registryRefetchStep{
					{FromDID: oldDID, ExpectedStatus: "verification_stale"},
					{AdvanceSeconds: 10, FromDID: oldDID, ExpectedStatus: "verification_stale"},
				},
				ExpectedRequests: map[string]int{addressPath: 2, keyPath: 0},
			},
		},
	}
}

func encodedRegistryRefetchVector(t *testing.T) []byte {
	t.Helper()
	data, err := json.MarshalIndent(buildRegistryRefetchVector(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

// The frozen vector is what the generator builds. Re-freezing is a reviewed
// decision: run with AWEB_FREEZE_REGISTRY_REFETCH_VECTOR=1 to rewrite it.
func TestRegistryRefetchVectorIsFrozen(t *testing.T) {
	want := encodedRegistryRefetchVector(t)
	if os.Getenv("AWEB_FREEZE_REGISTRY_REFETCH_VECTOR") == "1" {
		if err := os.WriteFile(filepath.FromSlash(registryRefetchVectorPath), want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.FromSlash(registryRefetchVectorPath))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(got); sum != sha256.Sum256(want) {
		t.Fatalf("%s differs from the generator; re-freeze only by a reviewed decision", registryRefetchVectorPath)
	}
}

func TestRegistryRefetchConformance(t *testing.T) {
	data, err := os.ReadFile(filepath.FromSlash(registryRefetchVectorPath))
	if err != nil {
		t.Fatal(err)
	}
	var vector registryRefetchVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Schema != "aweb.trust.registry-refetch.v1" {
		t.Fatalf("schema=%q", vector.Schema)
	}
	start, err := time.Parse(time.RFC3339, vector.StartTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range vector.Vectors {
		t.Run(tc.Name, func(t *testing.T) {
			var mu sync.Mutex
			served := map[string]int{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				queue, ok := tc.Responses[r.URL.Path]
				n := served[r.URL.Path]
				served[r.URL.Path] = n + 1
				mu.Unlock()
				if !ok {
					http.NotFound(w, r)
					return
				}
				answer := queue[min(n, len(queue)-1)]
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(answer.Status)
				if len(answer.Body) > 0 {
					_, _ = w.Write(answer.Body)
				}
			}))
			t.Cleanup(server.Close)

			now := start
			resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
			routeUntrustedResolverRegistriesToInjectedClient(resolver)
			resolver.Now = func() time.Time { return now }
			resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{value: DomainAuthority{RegistryURL: server.URL}, expiresAt: start.Add(time.Hour)}
			client, err := New("http://example")
			if err != nil {
				t.Fatal(err)
			}
			client.SetResolver(resolver)

			for i, step := range tc.Steps {
				now = now.Add(time.Duration(step.AdvanceSeconds) * time.Second)
				status := client.checkStableIdentityRegistry(context.Background(), Verified, tc.Address, step.FromDID, tc.FromStableID).status
				if string(status) != step.ExpectedStatus {
					t.Fatalf("step %d: status=%q, want %q", i, status, step.ExpectedStatus)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			for path, want := range tc.ExpectedRequests {
				if served[path] != want {
					t.Errorf("requests to %s=%d, want %d", path, served[path], want)
				}
			}
		})
	}
}
