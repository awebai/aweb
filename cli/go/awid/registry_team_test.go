package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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
		Team:          "backend:acme.com",
		MemberDIDKey:  ComputeDIDKey(memberPub),
		Alias:         "alice",
		IdentityScope: IdentityModeGlobal,
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

func TestRegisterCertificateAlreadyRegisteredTypedError(t *testing.T) {
	t.Parallel()

	_, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignTeamCertificate(teamKey, TeamCertificateFields{
		Team:          "backend:acme.com",
		MemberDIDKey:  ComputeDIDKey(memberPub),
		Alias:         "alice",
		IdentityScope: IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"detail": map[string]any{
				"code":    RegistryCodeCertificateAlreadyRegistered,
				"message": "Certificate already registered",
			},
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(server.Client(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = client.RegisterCertificate(ctx, server.URL, "acme.com", "backend", cert, teamKey)
	if err == nil {
		t.Fatal("expected error")
	}
	var alreadyRegistered *CertificateAlreadyRegisteredError
	if !errors.As(err, &alreadyRegistered) {
		t.Fatalf("error %T %[1]v is not CertificateAlreadyRegisteredError", err)
	}
	if alreadyRegistered.CertificateID != cert.CertificateID {
		t.Fatalf("certificate_id=%q want %q", alreadyRegistered.CertificateID, cert.CertificateID)
	}
	if alreadyRegistered.StatusCode != http.StatusConflict {
		t.Fatalf("status=%d", alreadyRegistered.StatusCode)
	}
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
		Team:          "backend:acme.com",
		MemberDIDKey:  ComputeDIDKey(memberPub),
		Alias:         "alice",
		IdentityScope: IdentityModeGlobal,
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
			"identity_scope": "global",
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
					"identity_scope": "global",
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
			"identity_scope": "global",
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

// pagedCertificateServer serves count certificates with keyset pagination, so a
// client that reads only the first page cannot see the later ones. The cursor is
// the offset of the next certificate. maxPageSize is the largest page this server
// will serve whatever the client asks for, which both mirrors a registry clamping
// to its own ceiling and keeps the fixture forcing several pages regardless of the
// page size the client happens to request.
func pagedCertificateServer(t *testing.T, count, maxPageSize int, requests *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests != nil {
			*requests = append(*requests, r.URL.String())
		}
		limit := maxPageSize
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				t.Fatalf("limit=%q is not a number", raw)
			}
			if parsed < 1 || parsed > 200 {
				t.Fatalf("limit=%d outside the registry range [1,200]", parsed)
			}
			if parsed < limit {
				limit = parsed
			}
		}
		offset := 0
		if raw := r.URL.Query().Get("cursor"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				t.Fatalf("cursor=%q was not one this server issued", raw)
			}
			offset = parsed
		}
		end := offset + limit
		if end > count {
			end = count
		}
		items := make([]map[string]any, 0, end-offset)
		for index := offset; index < end; index++ {
			items = append(items, map[string]any{
				"certificate_id": "cert-" + strconv.Itoa(index),
				"team_id":        "backend:acme.com",
				"member_did_key": "did:key:z6Mk" + strconv.Itoa(index),
				"alias":          "member-" + strconv.Itoa(index),
				"identity_scope": "global",
				"issued_at":      "2026-04-06T00:00:00Z",
			})
		}
		body := map[string]any{"certificates": items, "has_more": end < count}
		if end < count {
			body["next_cursor"] = strconv.Itoa(end)
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestListCertificatesReturnsEveryCertificateBeyondTheFirstPage(t *testing.T) {
	t.Parallel()

	// 120 certificates against a registry defaulting to 50 per page: a client that
	// takes the default and stops sees 50 and cannot tell that it did.
	const total = 120
	var requests []string
	server := pagedCertificateServer(t, total, 50, &requests)
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certs, err := client.ListCertificates(ctx, server.URL, "acme.com", "backend", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != total {
		t.Fatalf("got %d certificates, want %d", len(certs), total)
	}
	for index, cert := range certs {
		if want := "member-" + strconv.Itoa(index); cert.Alias != want {
			t.Fatalf("certs[%d].Alias=%q want %q", index, cert.Alias, want)
		}
	}
	// A target deliberately placed past the first page, named so a failure says
	// which one went missing rather than only that the count was short.
	found := false
	for _, cert := range certs {
		if cert.Alias == "member-117" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("member-117 is past the first page and is missing from the listing")
	}
	if len(requests) < 2 {
		t.Fatalf("made %d requests; a complete listing of %d needs more than one page", len(requests), total)
	}
	for _, request := range requests {
		if !strings.Contains(request, "active_only=true") {
			t.Fatalf("request %q dropped active_only", request)
		}
	}
}

func TestListCertificatesRefusesToReturnATruncatedListing(t *testing.T) {
	t.Parallel()

	// A registry that reports more pages but hands back no cursor to reach them.
	// The listing cannot be completed, so it must not be returned as one.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{{
				"certificate_id": "cert-1",
				"team_id":        "backend:acme.com",
				"member_did_key": "did:key:z6MkAlice",
				"alias":          "alice",
				"identity_scope": "global",
				"issued_at":      "2026-04-06T00:00:00Z",
			}},
			"has_more": true,
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certs, err := client.ListCertificates(ctx, server.URL, "acme.com", "backend", true)
	if err == nil {
		t.Fatalf("got %d certificates and no error; a listing that cannot be completed must not read as complete", len(certs))
	}
	if certs != nil {
		t.Fatalf("got %d certificates alongside the error; a partial list must not be returned", len(certs))
	}
	// Named specifically: all three truncation guards say "truncated", so a
	// substring that loose would pass whichever one fired.
	if !strings.Contains(err.Error(), "no cursor to reach them") {
		t.Fatalf("err=%v; the error must name the missing cursor as the cause", err)
	}
}

func TestListCertificatesRefusesAListingWhoseCursorNeverAdvances(t *testing.T) {
	t.Parallel()

	// A registry that keeps reporting more pages while handing back the cursor
	// the client just used. Following it would loop forever; trusting it would
	// return the first page as the whole team.
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests > 20 {
			t.Fatal("client kept following a cursor that never advanced")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{{
				"certificate_id": "cert-1",
				"team_id":        "backend:acme.com",
				"member_did_key": "did:key:z6MkAlice",
				"alias":          "alice",
				"identity_scope": "global",
				"issued_at":      "2026-04-06T00:00:00Z",
			}},
			"has_more":    true,
			"next_cursor": "stuck",
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certs, err := client.ListCertificates(ctx, server.URL, "acme.com", "backend", true)
	if err == nil {
		t.Fatalf("got %d certificates and no error from a cursor that never advanced", len(certs))
	}
	if certs != nil {
		t.Fatalf("got %d certificates alongside the error; a partial list must not be returned", len(certs))
	}
	if !strings.Contains(err.Error(), "repeated cursor") {
		t.Fatalf("err=%v; the error must name the stuck cursor as the cause", err)
	}
}

func TestListCertificatesRefusesToReturnWhatItGatheredAtThePageCap(t *testing.T) {
	t.Parallel()

	// A registry that never stops reporting more pages. The walk is bounded, and
	// what it has gathered at the bound is a prefix — returning it is exactly the
	// short-list-reads-as-complete defect this whole change exists to remove.
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{{
				"certificate_id": "cert-" + strconv.Itoa(requests),
				"team_id":        "backend:acme.com",
				"member_did_key": "did:key:z6Mk" + strconv.Itoa(requests),
				"alias":          "member-" + strconv.Itoa(requests),
				"identity_scope": "global",
				"issued_at":      "2026-04-06T00:00:00Z",
			}},
			"has_more":    true,
			"next_cursor": "page-" + strconv.Itoa(requests+1),
		})
	}))
	defer server.Close()

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	certs, err := client.ListCertificates(ctx, server.URL, "acme.com", "backend", true)
	if err == nil {
		t.Fatalf("got %d certificates and no error; the walk hit its bound and returned a prefix as complete", len(certs))
	}
	if certs != nil {
		t.Fatalf("got %d certificates alongside the error; a partial list must not be returned", len(certs))
	}
	if !strings.Contains(err.Error(), "after "+strconv.Itoa(certificateListPageCap)+" pages") {
		t.Fatalf("err=%v; the error must name the page cap as the cause", err)
	}
	if requests != certificateListPageCap {
		t.Fatalf("made %d requests, want exactly the cap of %d", requests, certificateListPageCap)
	}
}
