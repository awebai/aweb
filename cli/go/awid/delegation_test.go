package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type delegationVector struct {
	ParentControllerDID string                     `json:"parent_controller_did"`
	Payload             NamespaceDelegationPayload `json:"payload"`
	CanonicalJSONUTF8   string                     `json:"canonical_json_utf8"`
	EntryHash           string                     `json:"entry_hash"`
	ParentSignature     string                     `json:"parent_signature"`
	ChildSeedHex        string                     `json:"child_seed_hex"`
}

func TestNamespaceDelegationVector(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/namespace-delegation-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector delegationVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalNamespaceDelegationPayload(vector.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != vector.CanonicalJSONUTF8 {
		t.Fatalf("canonical payload mismatch\n got %s\nwant %s", canonical, vector.CanonicalJSONUTF8)
	}
	if got := NamespaceDelegationEntryHash(canonical); got != vector.EntryHash {
		t.Fatalf("entry hash=%s, want %s", got, vector.EntryHash)
	}
	if err := VerifyNamespaceDelegationSignature(vector.ParentControllerDID, vector.ParentSignature, canonical); err != nil {
		t.Fatal(err)
	}
}

func TestNamespaceDelegationJSONRejectsUnknownAndInvalidShapes(t *testing.T) {
	raw, _ := os.ReadFile("../../../docs/vectors/namespace-delegation-v1.json")
	var vector delegationVector
	_ = json.Unmarshal(raw, &vector)
	base := map[string]any{
		"payload":    vector.Payload,
		"entry_hash": vector.EntryHash,
		"signatures": []map[string]string{{
			"controller_did": vector.ParentControllerDID,
			"signature":      vector.ParentSignature,
		}},
	}
	cases := []func(map[string]any){
		func(value map[string]any) { value["unknown"] = true },
		func(value map[string]any) {
			payload := asMap(value["payload"])
			payload["operation"] = "invalid"
			value["payload"] = payload
		},
		func(value map[string]any) {
			payload := asMap(value["payload"])
			payload["parent_domain"] = "other.example"
			value["payload"] = payload
		},
		func(value map[string]any) {
			payload := asMap(value["payload"])
			payload["sequence"] = 2
			payload["previous_delegation_hash"] = nil
			value["payload"] = payload
		},
		func(value map[string]any) {
			value["signatures"] = []map[string]string{{
				"controller_did": vector.ParentControllerDID,
				"signature":      vector.ParentSignature + "=",
			}}
		},
	}
	for index, mutate := range cases {
		encoded, _ := json.Marshal(base)
		var value map[string]any
		_ = json.Unmarshal(encoded, &value)
		mutate(value)
		encoded, _ = json.Marshal(value)
		var assertion NamespaceDelegationAssertion
		if err := json.Unmarshal(encoded, &assertion); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
	valid := NamespaceDelegationAssertion{
		Payload: vector.Payload, EntryHash: vector.EntryHash,
		Signatures: []NamespaceDelegationSignature{{
			ControllerDID: vector.ParentControllerDID, Signature: vector.ParentSignature,
		}},
	}
	invalidOperation := valid
	invalidOperation.Payload.Operation = "invalid"
	invalidDomain := valid
	invalidDomain.Payload.ParentDomain = "other.example"
	invalidController := valid
	invalidController.Payload.ChildControllerDID = "did:key:invalid"
	invalidPredecessor := valid
	invalidPredecessor.Payload.Sequence = 2
	invalidPredecessor.Payload.PreviousDelegationHash = nil
	invalidHash := valid
	invalidHash.EntryHash = "sha256:" + strings.Repeat("0", 64)
	for index, assertion := range []NamespaceDelegationAssertion{
		invalidOperation, invalidDomain, invalidController, invalidPredecessor, invalidHash,
	} {
		if err := ValidateNamespaceDelegationAssertion(assertion); err == nil {
			t.Fatalf("constructed case %d accepted", index)
		}
	}
}

func asMap(value any) map[string]any {
	encoded, _ := json.Marshal(value)
	var result map[string]any
	_ = json.Unmarshal(encoded, &result)
	return result
}

func TestNamespaceDelegationSignatureRejectsPaddedAndTampered(t *testing.T) {
	raw, _ := os.ReadFile("../../../docs/vectors/namespace-delegation-v1.json")
	var vector delegationVector
	_ = json.Unmarshal(raw, &vector)
	canonical, _ := CanonicalNamespaceDelegationPayload(vector.Payload)
	if err := VerifyNamespaceDelegationSignature(vector.ParentControllerDID, vector.ParentSignature+"=", canonical); err == nil {
		t.Fatal("padded signature accepted")
	}
	canonical[0] ^= 1
	if err := VerifyNamespaceDelegationSignature(vector.ParentControllerDID, vector.ParentSignature, canonical); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestDelegatedRecoveryClientCarriesAssertionAndDualProof(t *testing.T) {
	_, newKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newKey.Public().(ed25519.PublicKey))
	_, parentKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	parentDID := ComputeDIDKey(parentKey.Public().(ed25519.PublicKey))
	previous := "sha256:" + strings.Repeat("0", 64)
	payload := NamespaceDelegationPayload{
		Version: NamespaceDelegationVersion, Operation: "rotate",
		ParentDomain: "grand.example", ChildDomain: "parent.grand.example",
		ChildControllerDID: newDID, Sequence: 2,
		PreviousDelegationHash: &previous,
	}
	canonical, _ := CanonicalNamespaceDelegationPayload(payload)
	assertion := NamespaceDelegationAssertion{
		Payload:   payload,
		EntryHash: NamespaceDelegationEntryHash(canonical),
		Signatures: []NamespaceDelegationSignature{{
			ControllerDID: parentDID,
			Signature:     base64.RawStdEncoding.EncodeToString(ed25519.Sign(parentKey, canonical)),
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AWEB-New-Controller-Authorization") == "" || r.Header.Get("X-AWEB-New-Controller-Timestamp") == "" {
			t.Fatal("missing new-controller proof headers")
		}
		var body controllerRolloverStartRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.RecoveryMode != "delegated" || body.RecoveryAssertion == nil || body.RecoveryAssertion.EntryHash != assertion.EntryHash {
			t.Fatalf("body=%+v", body)
		}
		_ = json.NewEncoder(w).Encode(NamespaceControllerRollover{
			RolloverID: "rollover", ParentDomain: "parent.grand.example",
			NewControllerDID: newDID, State: "ready",
		})
	}))
	defer server.Close()
	client := &RegistryClient{DefaultRegistryURL: server.URL, HTTPClient: server.Client()}
	if _, err := client.StartDelegatedControllerRecoveryAt(
		context.Background(), server.URL, "parent.grand.example", newDID, newKey, assertion,
	); err != nil {
		t.Fatal(err)
	}
}

func TestExactDNSRecoveryClientCarriesStrictModeAndDualProof(t *testing.T) {
	_, newKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newKey.Public().(ed25519.PublicKey))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.Header.Get("X-AWEB-New-Controller-Authorization") == "" {
				t.Fatal("missing new-controller proof")
			}
			var body controllerRolloverStartRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.RecoveryMode != ControllerRolloverRecoveryExactDNS || body.RecoveryAssertion != nil {
				t.Fatalf("body=%+v", body)
			}
		}
		_ = json.NewEncoder(w).Encode(NamespaceControllerRollover{
			RolloverID: "rollover", ParentDomain: "exact.example",
			NewControllerDID: newDID, State: "ready",
		})
	}))
	defer server.Close()
	client := &RegistryClient{DefaultRegistryURL: server.URL, HTTPClient: server.Client()}
	started, err := client.StartExactDNSControllerRecoveryAt(
		context.Background(), server.URL, "exact.example", newDID, newKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := client.GetControllerRolloverAt(
		context.Background(), server.URL, "exact.example", "rollover",
	)
	if err != nil || resumed.State != started.State {
		t.Fatalf("resumed=%+v err=%v", resumed, err)
	}
}

func TestDirectRotationAndReverifyCarryRolloverID(t *testing.T) {
	_, key, _ := GenerateKeypair()
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	seen := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		seen[r.URL.Path] = body["rollover_id"].(string)
		if strings.HasSuffix(r.URL.Path, "/reverify") {
			_ = json.NewEncoder(w).Encode(NamespaceReverifyResult{Domain: "parent.example"})
			return
		}
		_ = json.NewEncoder(w).Encode(RegistryNamespace{Domain: "parent.example"})
	}))
	defer server.Close()
	client := &RegistryClient{DefaultRegistryURL: server.URL, HTTPClient: server.Client()}
	if _, err := client.RotateNamespaceControllerAt(
		context.Background(), server.URL, "parent.example", did, key, "rollover-id",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReverifyNamespaceWithRolloverAt(
		context.Background(), server.URL, "parent.example", "rollover-id",
	); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("seen=%v", seen)
	}
	for path, value := range seen {
		if value != "rollover-id" {
			t.Fatalf("%s rollover=%q", path, value)
		}
	}
}

func TestCollectNamespaceDelegationLogRejectsEmptyActiveChain(t *testing.T) {
	raw, _ := os.ReadFile("../../../docs/vectors/namespace-delegation-v1.json")
	var vector delegationVector
	_ = json.Unmarshal(raw, &vector)
	assertion := NamespaceDelegationAssertion{
		Payload: vector.Payload, EntryHash: vector.EntryHash,
		Signatures: []NamespaceDelegationSignature{{
			ControllerDID: vector.ParentControllerDID, Signature: vector.ParentSignature,
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/delegation-log") {
			_ = json.NewEncoder(w).Encode(NamespaceDelegationLogPage{
				Entries:      []NamespaceDelegationAssertion{assertion},
				NextSequence: 1, HeadSequence: 1, HeadHash: vector.EntryHash,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(RegistryNamespace{
			Domain: "child.example.com", DelegationChain: nil,
		})
	}))
	defer server.Close()
	client := &RegistryClient{DefaultRegistryURL: server.URL, HTTPClient: server.Client()}
	_, err := client.CollectNamespaceDelegationLogAt(
		context.Background(), server.URL, "child.example.com", 0, 100, 0,
	)
	if err == nil || !strings.Contains(err.Error(), "omitted delegation chain") {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectNamespaceDelegationLogProtocolNegativesAndDeletedTombstone(t *testing.T) {
	raw, _ := os.ReadFile("../../../docs/vectors/namespace-delegation-v1.json")
	var vector delegationVector
	_ = json.Unmarshal(raw, &vector)
	delegate := NamespaceDelegationAssertion{
		Payload: vector.Payload, EntryHash: vector.EntryHash,
		Signatures: []NamespaceDelegationSignature{{
			ControllerDID: vector.ParentControllerDID, Signature: vector.ParentSignature,
		}},
	}
	seed, _ := hex.DecodeString(vector.ChildSeedHex)
	childKey := ed25519.NewKeyFromSeed(seed)
	previous := vector.EntryHash
	revokePayload := NamespaceDelegationPayload{
		Version: NamespaceDelegationVersion, Operation: "revoke",
		ParentDomain:       vector.Payload.ParentDomain,
		ChildDomain:        vector.Payload.ChildDomain,
		ChildControllerDID: vector.Payload.ChildControllerDID,
		Sequence:           2, PreviousDelegationHash: &previous,
	}
	revokeCanonical, _ := CanonicalNamespaceDelegationPayload(revokePayload)
	revoke := NamespaceDelegationAssertion{
		Payload: revokePayload, EntryHash: NamespaceDelegationEntryHash(revokeCanonical),
		Signatures: []NamespaceDelegationSignature{{
			ControllerDID: vector.Payload.ChildControllerDID,
			Signature:     base64.RawStdEncoding.EncodeToString(ed25519.Sign(childKey, revokeCanonical)),
		}},
	}
	cases := []struct {
		name    string
		page    NamespaceDelegationLogPage
		deleted bool
		wantErr string
	}{
		{name: "repeated", page: NamespaceDelegationLogPage{
			Entries:      []NamespaceDelegationAssertion{delegate, delegate},
			NextSequence: 2, HeadSequence: 2, HeadHash: delegate.EntryHash,
		}, wantErr: "not contiguous"},
		{name: "head mismatch", page: NamespaceDelegationLogPage{
			Entries:      []NamespaceDelegationAssertion{delegate},
			NextSequence: 1, HeadSequence: 1, HeadHash: "sha256:" + strings.Repeat("f", 64),
		}, wantErr: "final entry"},
		{name: "cursor mismatch", page: NamespaceDelegationLogPage{
			Entries: []NamespaceDelegationAssertion{delegate}, HasMore: true,
			NextSequence: 1, HeadSequence: 2, HeadHash: revoke.EntryHash,
		}, wantErr: "cursor boundary"},
		{name: "active tombstone", page: NamespaceDelegationLogPage{
			Entries:      []NamespaceDelegationAssertion{delegate, revoke},
			NextSequence: 2, HeadSequence: 2, HeadHash: revoke.EntryHash,
		}, wantErr: "active namespace"},
		{name: "deleted tombstone", page: NamespaceDelegationLogPage{
			Entries:      []NamespaceDelegationAssertion{delegate, revoke},
			NextSequence: 2, HeadSequence: 2, HeadHash: revoke.EntryHash,
		}, deleted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/delegation-log") {
					_ = json.NewEncoder(w).Encode(tc.page)
					return
				}
				if tc.deleted {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"detail":"Namespace not found"}`))
					return
				}
				chain := []NamespaceDelegationAssertion{delegate}
				if len(tc.page.Entries) > 0 && tc.page.Entries[len(tc.page.Entries)-1].Payload.Operation == "revoke" {
					chain = tc.page.Entries
				}
				_ = json.NewEncoder(w).Encode(RegistryNamespace{
					Domain:          vector.Payload.ChildDomain,
					DelegationChain: chain,
				})
			}))
			defer server.Close()
			client := &RegistryClient{DefaultRegistryURL: server.URL, HTTPClient: server.Client()}
			page, err := client.CollectNamespaceDelegationLogAt(
				context.Background(), server.URL, vector.Payload.ChildDomain, 0, 100, 0,
			)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || page.Entries[len(page.Entries)-1].Payload.Operation != "revoke" {
				t.Fatalf("page=%+v err=%v", page, err)
			}
		})
	}
}

func TestCollectNamespaceDelegationLogRejectsRepeatedCursor(t *testing.T) {
	raw, _ := os.ReadFile("../../../docs/vectors/namespace-delegation-v1.json")
	var vector delegationVector
	_ = json.Unmarshal(raw, &vector)
	delegate := NamespaceDelegationAssertion{
		Payload: vector.Payload, EntryHash: vector.EntryHash,
		Signatures: []NamespaceDelegationSignature{{
			ControllerDID: vector.ParentControllerDID, Signature: vector.ParentSignature,
		}},
	}
	seed, _ := hex.DecodeString(vector.ChildSeedHex)
	childKey := ed25519.NewKeyFromSeed(seed)
	previous := vector.EntryHash
	revokePayload := NamespaceDelegationPayload{
		Version: NamespaceDelegationVersion, Operation: "revoke",
		ParentDomain: vector.Payload.ParentDomain, ChildDomain: vector.Payload.ChildDomain,
		ChildControllerDID: vector.Payload.ChildControllerDID,
		Sequence:           2, PreviousDelegationHash: &previous,
	}
	canonical, _ := CanonicalNamespaceDelegationPayload(revokePayload)
	revoke := NamespaceDelegationAssertion{
		Payload: revokePayload, EntryHash: NamespaceDelegationEntryHash(canonical),
		Signatures: []NamespaceDelegationSignature{{
			ControllerDID: vector.Payload.ChildControllerDID,
			Signature:     base64.RawStdEncoding.EncodeToString(ed25519.Sign(childKey, canonical)),
		}},
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		entry := delegate
		if calls > 1 {
			entry = revoke
		}
		_ = json.NewEncoder(w).Encode(NamespaceDelegationLogPage{
			Entries: []NamespaceDelegationAssertion{entry}, HasMore: true,
			NextSequence: entry.Payload.Sequence, NextCursor: "same-cursor",
			HeadSequence: 2, HeadHash: revoke.EntryHash,
		})
	}))
	defer server.Close()
	client := &RegistryClient{DefaultRegistryURL: server.URL, HTTPClient: server.Client()}
	_, err := client.CollectNamespaceDelegationLogAt(
		context.Background(), server.URL, vector.Payload.ChildDomain, 0, 1, 0,
	)
	if err == nil || !strings.Contains(err.Error(), "continuation cursor repeated") {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectNamespaceDelegationLogRestartsChangedSnapshot(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/namespace-delegation-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector delegationVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	assertion := NamespaceDelegationAssertion{
		Payload:   vector.Payload,
		EntryHash: vector.EntryHash,
		Signatures: []NamespaceDelegationSignature{{
			ControllerDID: vector.ParentControllerDID,
			Signature:     vector.ParentSignature,
		}},
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/namespaces/child.example.com" {
			_ = json.NewEncoder(w).Encode(RegistryNamespace{
				Domain:          "child.example.com",
				DelegationChain: []NamespaceDelegationAssertion{assertion},
			})
			return
		}
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(NamespaceDelegationLogPage{
				Entries: []NamespaceDelegationAssertion{assertion},
				HasMore: true, NextSequence: 1, NextCursor: "cursor-one",
				HeadSequence: 2, HeadHash: "sha256:old",
			})
			return
		}
		if calls == 2 {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"detail":{"code":"delegation_log_snapshot_changed","message":"changed","retryable":true}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(NamespaceDelegationLogPage{
			Entries: []NamespaceDelegationAssertion{assertion},
			HasMore: false, NextSequence: 1, HeadSequence: 1, HeadHash: vector.EntryHash,
		})
	}))
	defer server.Close()
	client := &RegistryClient{DefaultRegistryURL: server.URL, HTTPClient: server.Client()}
	page, err := client.CollectNamespaceDelegationLogAt(
		context.Background(), server.URL, "child.example.com", 0, 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 4 || len(page.Entries) != 1 || page.Entries[0].EntryHash != vector.EntryHash {
		t.Fatalf("calls=%d page=%+v", calls, page)
	}
}
