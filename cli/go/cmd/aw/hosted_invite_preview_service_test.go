package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The preview request addresses <origin>/api/v1 whether the accept's service
// URL is the origin or its /api mount, so both name the same service; a
// different scheme, host or port is another service.
func TestHostedInvitePreviewTreatsTheAPIMountAsTheSameService(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		if r.URL.Path != "/api/v1/spawn/invite-preview" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"canonical_team_id": "backend:example.test",
			"identity_scope":    "local",
			"server_url":        serverURL,
			"expires_at":        nil,
			"status":            "active",
		})
	}))
	defer server.Close()
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	otherScheme := "https://" + strings.TrimPrefix(server.URL, "http://")

	for _, tc := range []struct {
		name, origin, serverURL, code string
	}{
		{"origin, service names its /api mount", server.URL, server.URL + "/api", ""},
		{"/api mount, service names its origin", server.URL + "/api", server.URL, ""},
		{"both the /api mount", server.URL + "/api", server.URL + "/api", ""},
		{"another port", server.URL, other.URL + "/api", "server_mismatch"},
		{"another scheme", server.URL, otherScheme + "/api", "server_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverURL = tc.serverURL
			_, wire, err := readHostedInvitePreview(context.Background(), "aw_inv_previewfixture", hostedJoinTokenEnvelope{AwebURL: tc.origin})
			if tc.code == "" {
				if err != nil || wire == nil || wire.Status != "active" {
					t.Fatalf("preview of the same service refused: %v", err)
				}
				return
			}
			if err == nil || err.Code != tc.code {
				t.Fatalf("preview error %v, want %s", err, tc.code)
			}
		})
	}
}
