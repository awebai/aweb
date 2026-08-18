package awid

// Tests for the client side of the registry's read-side team visibility gate
// (awid_service/routes/teams.py). The fake below enforces the gate the way
// the real service does: for a team not marked public, a read must carry a
// path-signature - "timestamp\nMETHOD\npath" signed by a did:key presented in
// the Authorization header - from the team controller key or an unrevoked
// member key, or it is answered 403 with detail code "team_private".

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// teamVisibilityGate is the fake registry's copy of _require_team_read_access.
type teamVisibilityGate struct {
	t          *testing.T
	visibility string
	teamDID    string
	memberDIDs map[string]bool

	// sawAuthorization records whether any request arrived carrying an
	// Authorization header, so anonymous-read tests can assert the client
	// sent none.
	sawAuthorization bool
}

// admit implements the gate. It returns true when the read may proceed and
// otherwise writes the service's real 403 team_private JSON shape.
func (g *teamVisibilityGate) admit(w http.ResponseWriter, r *http.Request) bool {
	g.t.Helper()
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		g.sawAuthorization = true
	}
	if g.visibility == "public" {
		return true
	}
	if did, ok := g.verifyPathSignature(r); ok {
		if did == g.teamDID || g.memberDIDs[did] {
			return true
		}
	}
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"detail": map[string]any{
			"code": "team_private",
			"message": "Team is private; reads require a same-team signed request " +
				"or the trusted service token",
		},
	})
	return false
}

// verifyPathSignature mirrors _verify_path_signature: DIDKey authorization
// header, a timestamp within a loose skew window, and an Ed25519 signature
// over "timestamp\nMETHOD\npath" - the path only, never the query string.
func (g *teamVisibilityGate) verifyPathSignature(r *http.Request) (string, bool) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 3 || parts[0] != "DIDKey" {
		return "", false
	}
	did, sigB64 := parts[1], parts[2]
	ts := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
	if ts == "" {
		return "", false
	}
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "", false
	}
	if delta := time.Since(parsed); delta > 5*time.Minute || delta < -5*time.Minute {
		return "", false
	}
	pub, err := ExtractPublicKey(did)
	if err != nil {
		return "", false
	}
	sig, err := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", false
	}
	payload := ts + "\n" + r.Method + "\n" + r.URL.Path
	if !ed25519.Verify(pub, []byte(payload), sig) {
		return "", false
	}
	return did, true
}

// newPrivateGateRegistry serves team get, member resolve, and a two-page
// certificate listing for backend:acme.com behind the visibility gate.
func newPrivateGateRegistry(t *testing.T, gate *teamVisibilityGate) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !gate.admit(w, r) {
			return
		}
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/teams/backend":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "backend:acme.com", "domain": "acme.com", "name": "backend",
				"display_name": "", "team_did_key": gate.teamDID,
				"visibility": gate.visibility, "created_at": "2026-08-01T00:00:00Z",
			})
		case "/v1/namespaces/acme.com/teams/backend/members/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "backend:acme.com", "certificate_id": "cert-alice",
				"member_did_key": "did:key:z6MkAlice", "alias": "alice",
				"identity_scope": "global", "issued_at": "2026-08-01T00:00:00Z",
			})
		case "/v1/namespaces/acme.com/teams/backend/certificates":
			// Two pages, so the paginated walk proves every page is signed
			// over the path alone even as the query string changes.
			page := map[string]any{
				"certificates": []map[string]any{{
					"certificate_id": "cert-alice", "team_id": "backend:acme.com",
					"member_did_key": "did:key:z6MkAlice", "alias": "alice",
					"identity_scope": "global", "issued_at": "2026-08-01T00:00:00Z",
				}},
				"has_more":    true,
				"next_cursor": "page-2",
			}
			if r.URL.Query().Get("cursor") == "page-2" {
				page = map[string]any{
					"certificates": []map[string]any{{
						"certificate_id": "cert-bob", "team_id": "backend:acme.com",
						"member_did_key": "did:key:z6MkBob", "alias": "bob",
						"identity_scope": "global", "issued_at": "2026-08-02T00:00:00Z",
					}},
					"has_more": false,
				}
			}
			_ = json.NewEncoder(w).Encode(page)
		default:
			t.Errorf("unexpected registry request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newPrivateBackendGate(t *testing.T) (*teamVisibilityGate, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	_, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	gate := &teamVisibilityGate{
		t:          t,
		visibility: "private",
		teamDID:    ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)),
		memberDIDs: map[string]bool{ComputeDIDKey(memberPub): true},
	}
	return gate, teamKey, memberKey
}

func TestPrivateTeamReadsSucceedWithMemberKey(t *testing.T) {
	t.Parallel()
	gate, _, memberKey := newPrivateBackendGate(t)
	server := newPrivateGateRegistry(t, gate)

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.GetTeam(ctx, server.URL, "acme.com", "backend", memberKey); err != nil {
		t.Fatalf("GetTeam: %v", err)
	}
	if _, err := client.ResolveTeamMember(ctx, server.URL, "acme.com", "backend", "alice", memberKey); err != nil {
		t.Fatalf("ResolveTeamMember: %v", err)
	}
	certs, err := client.ListCertificates(ctx, server.URL, "acme.com", "backend", true, memberKey)
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want both pages", len(certs))
	}
}

func TestPrivateTeamReadsSucceedWithControllerKey(t *testing.T) {
	t.Parallel()
	gate, teamKey, _ := newPrivateBackendGate(t)
	server := newPrivateGateRegistry(t, gate)

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.GetTeam(ctx, server.URL, "acme.com", "backend", teamKey); err != nil {
		t.Fatalf("GetTeam: %v", err)
	}
	if _, err := client.ResolveTeamMember(ctx, server.URL, "acme.com", "backend", "alice", teamKey); err != nil {
		t.Fatalf("ResolveTeamMember: %v", err)
	}
	certs, err := client.ListCertificates(ctx, server.URL, "acme.com", "backend", true, teamKey)
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want both pages", len(certs))
	}
}

func TestPrivateTeamUnsignedReadIsTeamPrivateError(t *testing.T) {
	t.Parallel()
	gate, _, _ := newPrivateBackendGate(t)
	server := newPrivateGateRegistry(t, gate)

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetTeam(ctx, server.URL, "acme.com", "backend", nil)
	if err == nil {
		t.Fatal("unsigned GetTeam of a private team succeeded")
	}
	if !IsTeamPrivateError(err) {
		t.Fatalf("IsTeamPrivateError=false for %v", err)
	}
	var regErr *RegistryError
	if !errors.As(err, &regErr) || regErr.Code != RegistryCodeTeamPrivate {
		t.Fatalf("parsed code=%q from %v", regErr.Code, err)
	}
	if gate.sawAuthorization {
		t.Fatal("an unsigned read sent an Authorization header")
	}
}

func TestPrivateTeamForeignKeyIsTeamPrivateError(t *testing.T) {
	t.Parallel()
	gate, _, _ := newPrivateBackendGate(t)
	server := newPrivateGateRegistry(t, gate)
	_, foreignKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, getErr := client.GetTeam(ctx, server.URL, "acme.com", "backend", foreignKey)
	if getErr == nil {
		t.Fatal("foreign-signed GetTeam of a private team succeeded")
	}
	if !IsTeamPrivateError(getErr) {
		t.Fatalf("IsTeamPrivateError=false for %v", getErr)
	}
}

func TestPublicTeamAnonymousReadIsUnchanged(t *testing.T) {
	t.Parallel()
	gate, _, _ := newPrivateBackendGate(t)
	gate.visibility = "public"
	server := newPrivateGateRegistry(t, gate)

	client := NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	team, err := client.GetTeam(ctx, server.URL, "acme.com", "backend", nil)
	if err != nil {
		t.Fatalf("GetTeam: %v", err)
	}
	if team.Name != "backend" {
		t.Fatalf("name=%q", team.Name)
	}
	member, err := client.ResolveTeamMember(ctx, server.URL, "acme.com", "backend", "alice", nil)
	if err != nil {
		t.Fatalf("ResolveTeamMember: %v", err)
	}
	if member.CertificateID != "cert-alice" {
		t.Fatalf("certificate_id=%q", member.CertificateID)
	}
	certs, err := client.ListCertificates(ctx, server.URL, "acme.com", "backend", true, nil)
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certificates", len(certs))
	}
	if gate.sawAuthorization {
		t.Fatal("an anonymous public read sent an Authorization header; anonymous behavior must be unchanged")
	}
}

func TestIsTeamPrivateErrorFallsBackToBodySubstring(t *testing.T) {
	t.Parallel()
	// A registry that answers 403 with an unstructured detail still carrying
	// the code is recognized; a 403 without the code is not.
	withCode := &RegistryError{
		StatusCode: http.StatusForbidden,
		Detail:     `{"detail": "team_private: reads require a signed request"}`,
	}
	if !IsTeamPrivateError(withCode) {
		t.Fatal("substring fallback did not recognize team_private")
	}
	otherForbidden := &RegistryError{
		StatusCode: http.StatusForbidden,
		Detail:     `{"detail": "Only the team controller can perform this action"}`,
	}
	if IsTeamPrivateError(otherForbidden) {
		t.Fatal("an unrelated 403 was read as team_private")
	}
	notForbidden := &RegistryError{
		StatusCode: http.StatusNotFound,
		Detail:     "team_private",
	}
	if IsTeamPrivateError(notForbidden) {
		t.Fatal("a non-403 was read as team_private")
	}
}
