package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
			"team_id":      "backend:acme.com",
			"domain":       "acme.com",
			"name":         "backend",
			"display_name": "Backend Team",
			"team_did_key": gotPayload["team_did_key"],
			"visibility":   "private",
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
	if team.TeamID != "backend:acme.com" {
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
			"team_id":      "backend:acme.com",
			"domain":       "acme.com",
			"name":         "backend",
			"display_name": "Backend Team",
			"team_did_key": "did:key:z6MkTeam",
			"visibility":   "public",
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
	if team.Visibility != "public" {
		t.Fatalf("visibility=%q", team.Visibility)
	}
}

func TestSetTeamVisibility(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDID := ComputeDIDKey(teamPub)

	var gotPayload map[string]any
	var gotAuthHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/visibility" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotAuthHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":      "backend:acme.com",
			"domain":       "acme.com",
			"name":         "backend",
			"display_name": "Backend Team",
			"team_did_key": teamDID,
			"visibility":   gotPayload["visibility"],
			"created_at":   "2026-04-06T00:00:00Z",
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	team, err := client.SetTeamVisibility(ctx, server.URL, "acme.com", "backend", "public", teamKey)
	if err != nil {
		t.Fatal(err)
	}
	if gotPayload["visibility"] != "public" {
		t.Fatalf("payload visibility=%v", gotPayload["visibility"])
	}
	if team.Visibility != "public" {
		t.Fatalf("visibility=%q", team.Visibility)
	}
	auth := strings.TrimSpace(gotAuthHeader)
	parts := strings.Split(auth, " ")
	if len(parts) != 3 || parts[0] != "DIDKey" {
		t.Fatalf("auth=%q", gotAuthHeader)
	}
	if parts[1] != teamDID {
		t.Fatalf("authorization DID=%s want team DID=%s", parts[1], teamDID)
	}
}

func TestSetTeamVisibilitySignsVisibilityInPayload(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDID := ComputeDIDKey(teamPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.Split(auth, " ")
		if len(parts) != 3 || parts[0] != "DIDKey" {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		if parts[1] != teamDID {
			t.Fatalf("authorization DID=%s want team DID=%s", parts[1], teamDID)
		}
		timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		payload := canonicalRegistryJSON(map[string]string{
			"domain":     "acme.com",
			"operation":  "set_team_visibility",
			"team_name":  "backend",
			"timestamp":  timestamp,
			"visibility": "public",
		})
		sig, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !ed25519.Verify(teamPub, []byte(payload), sig) {
			t.Fatalf("invalid team signature for payload %s", payload)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":      "backend:acme.com",
			"domain":       "acme.com",
			"name":         "backend",
			"display_name": "Backend Team",
			"team_did_key": teamDID,
			"visibility":   "public",
			"created_at":   "2026-04-06T00:00:00Z",
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.SetTeamVisibility(ctx, server.URL, "acme.com", "backend", "public", teamKey); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteTeam(t *testing.T) {
	t.Parallel()

	controllerPub, controllerKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := ComputeDIDKey(controllerPub)

	var gotBody deleteReasonRequest
	var gotAuthHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/namespaces/acme.com/teams/backend" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotAuthHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.DeleteTeam(
		ctx, server.URL, "acme.com", "backend", controllerKey, "cleanup after failed provision",
	); err != nil {
		t.Fatal(err)
	}
	if gotBody.Reason != "cleanup after failed provision" {
		t.Fatalf("reason=%q", gotBody.Reason)
	}
	if !strings.HasPrefix(gotAuthHeader, "DIDKey ") {
		t.Fatalf("auth header=%q", gotAuthHeader)
	}
	parts := strings.Split(gotAuthHeader, " ")
	if len(parts) != 3 {
		t.Fatalf("auth=%q", gotAuthHeader)
	}
	if parts[1] != controllerDID {
		t.Fatalf("authorization DID=%s want controller DID=%s", parts[1], controllerDID)
	}
}

func TestDeleteTeamSignsTeamNameInPayload(t *testing.T) {
	t.Parallel()

	controllerPub, controllerKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := ComputeDIDKey(controllerPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.Split(auth, " ")
		if len(parts) != 3 || parts[0] != "DIDKey" {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		if parts[1] != controllerDID {
			t.Fatalf("authorization DID=%s want controller DID=%s", parts[1], controllerDID)
		}
		timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		payload := canonicalRegistryJSON(map[string]string{
			"domain":    "acme.com",
			"operation": "delete_team",
			"team_name": "backend",
			"timestamp": timestamp,
		})
		sig, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !ed25519.Verify(controllerPub, []byte(payload), sig) {
			t.Fatalf("invalid controller signature for payload %s", payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.DeleteTeam(ctx, server.URL, "acme.com", "backend", controllerKey, ""); err != nil {
		t.Fatal(err)
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
		Team:         "backend:acme.com",
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
	encoded, err := EncodeTeamCertificateHeader(cert)
	if err != nil {
		t.Fatal(err)
	}
	if gotPayload["certificate"] != encoded {
		t.Fatalf("certificate blob not sent")
	}
	_ = teamPub
}

func TestFetchTeamCertificate(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignTeamCertificate(teamKey, TeamCertificateFields{
		Team:         "backend:acme.com",
		MemberDIDKey: ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeTeamCertificateHeader(cert)
	if err != nil {
		t.Fatal(err)
	}

	var gotAuth string
	var gotTimestamp string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/certificates/"+cert.CertificateID {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotAuth = strings.TrimSpace(r.Header.Get("Authorization"))
		gotTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":        "backend:acme.com",
			"certificate_id": cert.CertificateID,
			"member_did_key": cert.MemberDIDKey,
			"alias":          "alice",
			"lifetime":       "persistent",
			"issued_at":      cert.IssuedAt,
			"certificate":    encoded,
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := client.FetchTeamCertificate(ctx, server.URL, "acme.com", "backend", cert.CertificateID, memberKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertificateID != cert.CertificateID {
		t.Fatalf("certificate_id=%q", got.CertificateID)
	}
	if err := VerifyTeamCertificate(got, teamPub); err != nil {
		t.Fatalf("VerifyTeamCertificate: %v", err)
	}
	parts := strings.Fields(gotAuth)
	if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != cert.MemberDIDKey {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if gotTimestamp == "" {
		t.Fatal("missing X-AWEB-Timestamp")
	}
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
					"team_id":        "backend:acme.com",
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

func TestResolveTeamMember(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/members/alice" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":        "backend:acme.com",
			"certificate_id": "cert-1",
			"member_did_key": "did:key:z6MkAlice",
			"member_did_aw":  "did:aw:alice",
			"member_address": "acme.com/alice",
			"alias":          "alice",
			"lifetime":       "persistent",
			"issued_at":      "2026-04-06T00:00:00Z",
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	member, err := client.ResolveTeamMember(ctx, server.URL, "acme.com", "backend", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if member.TeamID != "backend:acme.com" {
		t.Fatalf("team_id=%q", member.TeamID)
	}
	if member.CertificateID != "cert-1" {
		t.Fatalf("certificate_id=%q", member.CertificateID)
	}
	if member.MemberAddress != "acme.com/alice" {
		t.Fatalf("member_address=%q", member.MemberAddress)
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

func TestDeleteTeamRequiresControllerSigningKey(t *testing.T) {
	t.Parallel()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.DeleteTeam(ctx, "https://registry.example.com", "acme.com", "backend", nil, "")
	if err == nil || !strings.Contains(err.Error(), "controller signing key is required") {
		t.Fatalf("err=%v", err)
	}
}
