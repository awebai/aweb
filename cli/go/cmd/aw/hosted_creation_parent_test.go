package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestHostedPersonParentUsesIndependentAccountRead(t *testing.T) {
	pub, _, _ := awid.GenerateKeypair()
	human := awid.ComputeStableID(pub)
	otherPub, _, _ := awid.GenerateKeypair()
	otherHuman := awid.ComputeStableID(otherPub)
	for _, tt := range []struct {
		name, raw, selected string
		root, ok            bool
	}{
		{"missing", `{"id":"account"}`, "", false, false},
		{"unavailable", `{"id":"account","human_identities":null}`, "", false, false},
		{"none", `{"id":"account","human_identities":[]}`, "", false, false},
		{"one", `{"id":"account","human_identities":[{"id":"` + human + `","domain":"example.test"}]}`, "", false, true},
		{"explicit", `{"id":"account","human_identities":[{"id":"` + human + `","domain":"example.test"}]}`, human, false, true},
		{"other", `{"id":"account","human_identities":[{"id":"` + human + `","domain":"example.test"}]}`, "did:aw:other", false, false},
		{"no-root-fallback", `{"id":"account","human_identities":[{"id":"` + human + `","domain":"example.test"}]}`, "", true, false},
		{"ambiguous", `{"id":"account","human_identities":[{"id":"` + human + `","domain":"example.test"},{"id":"` + otherHuman + `","domain":"other.test"}]}`, "", false, false},
		{"select-among-many", `{"id":"account","human_identities":[{"id":"` + human + `","domain":"example.test"},{"id":"` + otherHuman + `","domain":"other.test"}]}`, human, false, true},
		{"malformed", `{"id":"account","human_identities":[{"id":"bad","domain":"example.test"}]}`, "", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var account cliAuthAccount
			if err := json.Unmarshal([]byte(tt.raw), &account); err != nil {
				t.Fatal(err)
			}
			selected, err := selectHostedPersonParent(account, tt.selected, tt.root)
			if (err == nil) != tt.ok {
				t.Fatalf("selection %+v error %v", selected, err)
			}
			if tt.ok && (selected.ID != human || selected.Domain != "example.test") {
				t.Fatalf("wrong independent parent %+v", selected)
			}
		})
	}
}

func TestHostedChainlessGlobalOwnerRequiresFreshBoundUnenrolledKey(t *testing.T) {
	pub, key, _ := awid.GenerateKeypair()
	did, stable := awid.ComputeDIDKey(pub), awid.ComputeStableID(pub)
	for _, tt := range []struct {
		name, tree, stable, key string
		ok                      bool
	}{
		{"legacy", `{"enrolled":false}`, stable, did, true},
		{"enrolled", `{"enrolled":true,"domain":"example.test"}`, stable, did, false},
		{"missing", `null`, stable, did, false},
		{"malformed", `{"enrolled":"false"}`, stable, did, false},
		{"wrong-subject", `{"enrolled":false}`, "did:aw:other", did, false},
		{"wrong-key", `{"enrolled":false}`, stable, "did:key:other", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/key") {
					t.Errorf("unexpected read %s", r.URL.Path)
				}
				reads++
				json.NewEncoder(w).Encode(map[string]any{"did_aw": tt.stable, "current_did_key": tt.key, "id_tree": json.RawMessage(tt.tree)})
			}))
			defer server.Close()
			registry := awid.NewAWIDRegistryClient(nil, nil)
			registry.DefaultRegistryURL = server.URL
			owner := &hostedOwnerAuthority{did: did, key: key, stableID: stable, registryURL: server.URL}
			err := requireLegacyHostedOwner(context.Background(), owner, registry)
			if (err == nil) != tt.ok || reads != 1 {
				t.Fatalf("legacy=%v reads=%d error=%v", tt.ok, reads, err)
			}
		})
	}
}

func TestAPIKeyCreationParentComesFromThatKeysSelectedTeam(t *testing.T) {
	for _, tt := range []struct {
		name, canonical string
		ok              bool
	}{
		{"selected", "agents:tenant.example.test", true},
		{"missing", "", false},
		{"malformed", "tenant-slug", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/teams/current" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer fixture-key" {
					t.Error("team read used another path/credential")
				}
				json.NewEncoder(w).Encode(map[string]any{"team_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": tt.canonical, "slug": "untrusted-slug"})
			}))
			defer server.Close()
			selected, err := readAPIKeyCreationTeam(t.Context(), server.URL, "fixture-key")
			if (err == nil) != tt.ok {
				t.Fatalf("team %+v error %v", selected, err)
			}
			if tt.ok && (selected.Domain != "tenant.example.test" || selected.TeamID != "11111111-1111-4111-8111-111111111111") {
				t.Fatalf("parent was inferred from another field: %+v", selected)
			}
		})
	}
}

// A service that cannot answer the API key's team read says what is likely
// wrong: a 404 is a service older than this aw; a 401 or 403 is a wrong key
// or an older service, and the refusal says both.
func TestAPIKeyCreationTeamReadRefusalSaysWhatIsLikelyWrong(t *testing.T) {
	for _, tt := range []struct {
		status int
		want   string
	}{
		{http.StatusNotFound, "does not support creating agents with an API key; it is older than this aw. Use an aweb service that does, or an older aw."},
		{http.StatusUnauthorized, "refused this API key's team read (HTTP 401). Check that AWEB_API_KEY is current; if it is, the service may be older than this aw and not support creating agents with an API key."},
		{http.StatusForbidden, "refused this API key's team read (HTTP 403). Check that AWEB_API_KEY is current; if it is, the service may be older than this aw and not support creating agents with an API key."},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.status)
		}))
		_, err := readAPIKeyCreationTeam(t.Context(), server.URL, "fixture-key")
		server.Close()
		if err == nil || !strings.Contains(err.Error(), "The aweb service at ") || !strings.HasSuffix(err.Error(), tt.want) {
			t.Fatalf("HTTP %d: err=%v, want ...%q", tt.status, err, tt.want)
		}
	}
}
