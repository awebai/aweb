package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListNamespaces(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/namespaces" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Fatalf("auth=%q", auth)
		}
		_ = json.NewEncoder(w).Encode(ListNamespacesResponse{
			Namespaces: []Namespace{
				{Slug: "juan", Tier: "free", AgentCount: 2},
				{Slug: "mycompany", Tier: "paid", AgentCount: 5},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ListNamespaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Namespaces) != 2 {
		t.Fatalf("got %d namespaces, want 2", len(resp.Namespaces))
	}
	if resp.Namespaces[0].Slug != "juan" {
		t.Fatalf("slug=%q", resp.Namespaces[0].Slug)
	}
	if resp.Namespaces[0].Tier != "free" {
		t.Fatalf("tier=%q", resp.Namespaces[0].Tier)
	}
	if resp.Namespaces[0].AgentCount != 2 {
		t.Fatalf("agent_count=%d", resp.Namespaces[0].AgentCount)
	}
	if resp.Namespaces[1].Slug != "mycompany" {
		t.Fatalf("slug=%q", resp.Namespaces[1].Slug)
	}
}
