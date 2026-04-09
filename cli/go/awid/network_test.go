package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNetworkDirectorySearch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/network/directory" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.URL.Query().Get("capability") != "translate" {
			t.Fatalf("capability=%s", r.URL.Query().Get("capability"))
		}
		_ = json.NewEncoder(w).Encode(NetworkDirectoryResponse{
			Agents: []NetworkDirectoryAgent{{Domain: "acme", Alias: "translator", Capabilities: []string{"translate"}}},
			Total:  1,
		})
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	resp, err := c.NetworkDirectorySearch(context.Background(), NetworkDirectoryParams{Capability: "translate"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || resp.Agents[0].Alias != "translator" {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestNetworkDirectoryGet(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/network/directory/acme/researcher" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(NetworkDirectoryAgent{
			Domain:       "acme",
			OrgName:      "Acme Corp",
			Alias:        "researcher",
			Capabilities: []string{"research"},
			Description:  "Research agent",
		})
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	resp, err := c.NetworkDirectoryGet(context.Background(), "acme", "researcher")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Alias != "researcher" || resp.Domain != "acme" {
		t.Fatalf("resp=%+v", resp)
	}
}
