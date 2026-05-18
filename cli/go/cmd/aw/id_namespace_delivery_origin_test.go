package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIDNamespaceDeliveryOriginHappyPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}

	var patchCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":            "ns-acme",
				"domain":                  "acme.com",
				"controller_did":          controllerDID,
				"verification_status":     "verified",
				"default_delivery_origin": "https://old.example",
				"last_verified_at":        "2026-04-01T00:00:00Z",
				"created_at":              "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/namespaces/acme.com":
			patchCalls.Add(1)
			verifyCanonicalRegistryAuth(t, r, map[string]string{
				"domain":                  "acme.com",
				"operation":               "update_namespace",
				"default_delivery_origin": "https://aweb.acme.com",
			})
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["default_delivery_origin"] != "https://aweb.acme.com" {
				t.Fatalf("default_delivery_origin=%v", body["default_delivery_origin"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":            "ns-acme",
				"domain":                  "acme.com",
				"controller_did":          controllerDID,
				"verification_status":     "verified",
				"default_delivery_origin": "https://aweb.acme.com",
				"last_verified_at":        "2026-04-01T00:00:00Z",
				"created_at":              "2026-04-01T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	out, err := executeIDNamespaceDeliveryOrigin(context.Background(), idNamespaceDeliveryOriginOptions{
		Domain: "acme.com",
		Origin: "https://Aweb.Acme.Com/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "updated" {
		t.Fatalf("status=%q", out.Status)
	}
	if out.Origin != "https://aweb.acme.com" {
		t.Fatalf("origin=%q", out.Origin)
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("patch calls=%d", patchCalls.Load())
	}
}

func TestIDNamespaceDeliveryOriginUnchangedDoesNotPatch(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":            "ns-acme",
				"domain":                  "acme.com",
				"controller_did":          controllerDID,
				"verification_status":     "verified",
				"default_delivery_origin": "https://aweb.acme.com",
				"last_verified_at":        "2026-04-01T00:00:00Z",
				"created_at":              "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodPatch:
			t.Fatalf("unexpected PATCH")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	out, err := executeIDNamespaceDeliveryOrigin(context.Background(), idNamespaceDeliveryOriginOptions{
		Domain: "acme.com",
		Origin: "https://aweb.acme.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "unchanged" {
		t.Fatalf("status=%q", out.Status)
	}
}

func TestIDNamespaceDeliveryOriginControllerMismatch(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/acme.com" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"namespace_id":        "ns-acme",
			"domain":              "acme.com",
			"controller_did":      "did:key:z6Mkdifferent",
			"verification_status": "verified",
			"created_at":          "2026-04-01T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = executeIDNamespaceDeliveryOrigin(context.Background(), idNamespaceDeliveryOriginOptions{
		Domain: "acme.com",
		Origin: "https://aweb.acme.com",
	})
	if err == nil {
		t.Fatal("expected controller mismatch")
	}
	if got := err.Error(); !strings.Contains(got, "does not match registered controller") {
		t.Fatalf("err=%v", err)
	}
}
