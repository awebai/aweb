package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCreateTeam(t *testing.T) {
	t.Parallel()

	_, controllerKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var gotPayload map[string]any
	var gotAuthHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/acme.com/teams" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotAuthHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":      "team-uuid-1",
			"domain":       "acme.com",
			"name":         "backend",
			"team_did_key": gotPayload["team_did_key"],
			"created_at":   "2026-04-06T00:00:00Z",
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	team, err := client.CreateTeam(ctx, server.URL, "acme.com", "backend", "Backend Team", "did:key:z6MkTeam", controllerKey)
	if err != nil {
		t.Fatal(err)
	}
	if team.TeamID != "team-uuid-1" {
		t.Fatalf("team_id=%q", team.TeamID)
	}
	if team.Name != "backend" {
		t.Fatalf("name=%q", team.Name)
	}
	if gotPayload["name"] != "backend" {
		t.Fatalf("payload name=%v", gotPayload["name"])
	}
	if gotPayload["team_did_key"] != "did:key:z6MkTeam" {
		t.Fatalf("payload team_did_key=%v", gotPayload["team_did_key"])
	}
	if !strings.HasPrefix(gotAuthHeader, "DIDKey ") {
		t.Fatalf("auth header=%q", gotAuthHeader)
	}
}

func TestGetTeam(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/acme.com/teams/backend" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":      "team-uuid-1",
			"domain":       "acme.com",
			"name":         "backend",
			"team_did_key": "did:key:z6MkTeam",
			"created_at":   "2026-04-06T00:00:00Z",
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	team, err := client.GetTeam(ctx, server.URL, "acme.com", "backend")
	if err != nil {
		t.Fatal(err)
	}
	if team.TeamDIDKey != "did:key:z6MkTeam" {
		t.Fatalf("team_did_key=%q", team.TeamDIDKey)
	}
}

func TestRegisterCertificate(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := SignTeamCertificate(teamKey, TeamCertificateFields{
		TeamAddress:  "acme.com/backend",
		MemberDIDKey: ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/certificates" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.RegisterCertificate(ctx, server.URL, "acme.com", "backend", cert, teamKey); err != nil {
		t.Fatal(err)
	}
	if gotPayload["certificate_id"] != cert.CertificateID {
		t.Fatalf("certificate_id=%v", gotPayload["certificate_id"])
	}
	if gotPayload["member_did_key"] != ComputeDIDKey(memberPub) {
		t.Fatalf("member_did_key=%v", gotPayload["member_did_key"])
	}
	_ = teamPub
}

func TestListCertificates(t *testing.T) {
	t.Parallel()

	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{
				{
					"certificate_id": "cert-1",
					"team_address":   "acme.com/backend",
					"member_did_key": "did:key:z6MkAlice",
					"alias":          "alice",
					"lifetime":       "persistent",
					"issued_at":      "2026-04-06T00:00:00Z",
				},
			},
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certs, err := client.ListCertificates(ctx, server.URL, "acme.com", "backend", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certificates", len(certs))
	}
	if certs[0].Alias != "alice" {
		t.Fatalf("alias=%q", certs[0].Alias)
	}
	if !strings.Contains(gotPath, "active_only=true") {
		t.Fatalf("path=%q should contain active_only=true", gotPath)
	}
}

func TestRevokeCertificate(t *testing.T) {
	t.Parallel()

	_, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/certificates/revoke" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.RevokeCertificate(ctx, server.URL, "acme.com", "backend", "cert-42", teamKey); err != nil {
		t.Fatal(err)
	}
	if gotPayload["certificate_id"] != "cert-42" {
		t.Fatalf("certificate_id=%v", gotPayload["certificate_id"])
	}
}
