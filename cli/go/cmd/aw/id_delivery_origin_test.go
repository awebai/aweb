package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestIDDeliveryOriginSignsWithCurrentIdentityKey(t *testing.T) {
	tmp := t.TempDir()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	var putCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/did/"+stableID+"/delivery-origin" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		putCalls.Add(1)
		verifyCanonicalRegistryAuth(t, r, map[string]string{
			"did_aw":          stableID,
			"operation":       "set_delivery_origin",
			"delivery_origin": "https://aweb.acme.com",
		})
		if auth := r.Header.Get("Authorization"); !strings.Contains(auth, did) {
			t.Fatalf("authorization did=%q want %s", auth, did)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["delivery_origin"] != "https://aweb.acme.com" {
			t.Fatalf("delivery_origin=%v", body["delivery_origin"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did_aw":          stableID,
			"current_did_key": did,
			"delivery_origin": "https://aweb.acme.com",
			"created_at":      "2026-04-04T00:00:00Z",
			"updated_at":      "2026-04-04T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	writeSelfCustodyConfig(t, tmp, server.URL, "acme.com/alice", "acme.com", "alice", did, stableID, priv)
	t.Chdir(tmp)

	out, err := executeIDDeliveryOrigin(context.Background(), idDeliveryOriginOptions{
		Origin: "https://Aweb.Acme.Com/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "updated" || out.DIDAW != stableID || out.CurrentDIDKey != did || out.Origin != "https://aweb.acme.com" {
		t.Fatalf("unexpected output: %+v", out)
	}
	if putCalls.Load() != 1 {
		t.Fatalf("put calls=%d", putCalls.Load())
	}
}

func TestIDDeliveryOriginRejectsDifferentDIDAW(t *testing.T) {
	tmp := t.TempDir()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	writeSelfCustodyConfig(t, tmp, "https://registry.example", "acme.com/alice", "acme.com", "alice", did, stableID, priv)
	t.Chdir(tmp)

	_, err = executeIDDeliveryOrigin(context.Background(), idDeliveryOriginOptions{
		DIDAW:  "did:aw:other",
		Origin: "https://aweb.acme.com",
	})
	if err == nil {
		t.Fatal("expected did mismatch")
	}
	if !strings.Contains(err.Error(), "must match the current self-custodial identity") {
		t.Fatalf("err=%v", err)
	}
}
