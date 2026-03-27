package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateProject(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	var gotAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/create-project" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"project_id":     "proj-1",
			"project_slug":   "default",
			"namespace_slug": "myteam",
			"namespace":      "myteam.aweb.ai",
			"identity_id":    "identity-1",
			"alias":          "deploy-bot",
			"address":        "myteam.aweb.ai/deploy-bot",
			"api_key":        "aw_sk_headless_test",
			"did":            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			"stable_id":      "stable-1",
			"custody":        "self",
			"lifetime":       "persistent",
			"created":        true,
		})
	}))
	t.Cleanup(server.Close)

	// Unauthenticated client — create-project requires no credentials.
	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	name := "deploy-bot"
	resp, err := c.CreateProject(context.Background(), &CreateProjectRequest{
		ProjectSlug:   "default",
		NamespaceSlug: "myteam",
		Name:          &name,
		AgentType:     "agent",
		DID:           "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		PublicKey:     "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY",
		Custody:       CustodySelf,
		Lifetime:      LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	// No auth header for anonymous bootstrap.
	if gotAuth != "" {
		t.Fatalf("expected no auth header, got %q", gotAuth)
	}

	// Verify request body.
	if gotBody["namespace_slug"] != "myteam" {
		t.Fatalf("request namespace_slug=%v", gotBody["namespace_slug"])
	}
	if gotBody["name"] != "deploy-bot" {
		t.Fatalf("request name=%v", gotBody["name"])
	}
	if gotBody["did"] != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("request did=%v", gotBody["did"])
	}
	if gotBody["public_key"] != "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY" {
		t.Fatalf("request public_key=%v", gotBody["public_key"])
	}
	if gotBody["custody"] != "self" {
		t.Fatalf("request custody=%v", gotBody["custody"])
	}
	if gotBody["lifetime"] != "persistent" {
		t.Fatalf("request lifetime=%v", gotBody["lifetime"])
	}
	if gotBody["agent_type"] != "agent" {
		t.Fatalf("request agent_type=%v", gotBody["agent_type"])
	}

	// Verify response.
	if resp.IdentityID != "identity-1" {
		t.Fatalf("identity_id=%q", resp.IdentityID)
	}
	if resp.NamespaceSlug != "myteam" {
		t.Fatalf("namespace_slug=%q", resp.NamespaceSlug)
	}
	if resp.Namespace != "myteam.aweb.ai" {
		t.Fatalf("namespace=%q", resp.Namespace)
	}
	if resp.Alias != "deploy-bot" {
		t.Fatalf("alias=%q", resp.Alias)
	}
	if resp.Address != "myteam.aweb.ai/deploy-bot" {
		t.Fatalf("address=%q", resp.Address)
	}
	if resp.APIKey != "aw_sk_headless_test" {
		t.Fatalf("api_key=%q", resp.APIKey)
	}
	if resp.DID != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("did=%q", resp.DID)
	}
	if resp.StableID != "stable-1" {
		t.Fatalf("stable_id=%q", resp.StableID)
	}
	if resp.Custody != "self" {
		t.Fatalf("custody=%q", resp.Custody)
	}
	if resp.Lifetime != "persistent" {
		t.Fatalf("lifetime=%q", resp.Lifetime)
	}
	if !resp.Created {
		t.Fatal("created=false, want true")
	}
}

func TestCreateProjectHTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	alias := "deploy-bot"
	_, err = c.CreateProject(context.Background(), &CreateProjectRequest{
		ProjectSlug:   "default",
		NamespaceSlug: "myteam",
		Alias:         &alias,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	code, ok := HTTPStatusCode(err)
	if !ok || code != 429 {
		t.Fatalf("expected 429, got %d (ok=%v)", code, ok)
	}
}

func TestCreateProjectAllowsEphemeralAliasOmission(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/create-project" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"project_id":     "proj-1",
			"project_slug":   "default",
			"namespace_slug": "myteam",
			"namespace":      "myteam.aweb.ai",
			"identity_id":    "identity-1",
			"alias":          "alice",
			"address":        "myteam.aweb.ai/alice",
			"api_key":        "aw_sk_headless_test",
			"did":            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			"stable_id":      "stable-1",
			"custody":        "self",
			"lifetime":       "ephemeral",
			"created":        true,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.CreateProject(context.Background(), &CreateProjectRequest{
		ProjectSlug:   "default",
		NamespaceSlug: "myteam",
		AgentType:     "agent",
		DID:           "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		PublicKey:     "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY",
		Custody:       CustodySelf,
		Lifetime:      LifetimeEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["alias"]; ok {
		t.Fatalf("alias should be omitted, got %v", gotBody["alias"])
	}
	if resp.Alias != "alice" {
		t.Fatalf("alias=%q", resp.Alias)
	}
}
