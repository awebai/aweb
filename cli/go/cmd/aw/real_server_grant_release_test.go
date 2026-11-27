package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

type grantRevokeEnvelope struct {
	Status    string          `json:"status"`
	GrantID   string          `json:"grant_id"`
	RevokedAt string          `json:"revoked_at"`
	Release   *releaseReceipt `json:"release"`
	Error     *cliErrorBody   `json:"error"`
}

func decodeGrantRevoke(t *testing.T, out string) grantRevokeEnvelope {
	t.Helper()
	var answer grantRevokeEnvelope
	if err := json.Unmarshal([]byte(out), &answer); err != nil {
		t.Fatalf("revoke answer is not one JSON document: %v\n%s", err, out)
	}
	if answer.Release == nil {
		t.Fatalf("revoke answer has no release receipt:\n%s", out)
	}
	return answer
}

func mintGrantForRelease(t *testing.T, world *realCommandWorld, home string) string {
	t.Helper()
	out := world.requireCommand(t, home, "id", "grant", "mint", "--ttl", "5m", "--scope", "coord.read", "--out", filepath.Join(t.TempDir(), "grant"))
	var minted grantMintOutput
	if err := json.Unmarshal([]byte(out), &minted); err != nil || minted.GrantID == "" {
		t.Fatalf("mint: %v\n%s", err, out)
	}
	return minted.GrantID
}

func grantStatus(t *testing.T, world *realCommandWorld, home, grantID string) string {
	t.Helper()
	out := world.requireCommand(t, home, "id", "grant", "show", grantID)
	var shown struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &shown); err != nil {
		t.Fatalf("show: %v\n%s", err, out)
	}
	return shown.Status
}

// revocationDroppingProxy forwards every request to the real server except
// revokes, whose connection it closes after reading the request: the request
// was sent and never reached the server.
func revocationDroppingProxy(t *testing.T, serverURL string) *httptest.Server {
	t.Helper()
	target, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	forward := httputil.NewSingleHostReverseProxy(target)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/revoke") {
			forward.ServeHTTP(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		conn.Close()
	}))
	t.Cleanup(proxy.Close)
	return proxy
}

func TestRealServerGrantRevokeReceipt(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "resident")

	t.Run("confirmed and repeated", func(t *testing.T) {
		grantID := mintGrantForRelease(t, world, member.Home)
		first := decodeGrantRevoke(t, world.requireCommand(t, member.Home, "id", "grant", "revoke", grantID, "--expect-subject", "resident"))
		want := releaseReceipt{Effect: releaseRevokeGrant, TeamID: world.TeamID, Subject: first.Release.Subject, Target: releaseTarget{GrantID: grantID}, Outcome: releaseConfirmed}
		if first.Status != "revoked" || first.GrantID != grantID || first.RevokedAt == "" || *first.Release != want {
			t.Fatalf("first revoke=%+v release=%+v", first, *first.Release)
		}
		if first.Release.Subject.Alias != "resident" || !strings.HasPrefix(first.Release.Subject.DID, "did:key:") {
			t.Fatalf("subject is not the selected resident: %+v", first.Release.Subject)
		}
		again := decodeGrantRevoke(t, world.requireCommand(t, member.Home, "id", "grant", "revoke", grantID))
		if again.RevokedAt != first.RevokedAt || again.Release.Outcome != releaseConfirmed {
			t.Fatalf("repeat=%+v, want the original revocation confirmed", again)
		}
	})

	t.Run("wrong subject refuses before sending", func(t *testing.T) {
		grantID := mintGrantForRelease(t, world, member.Home)
		out, err := world.runInIdentityHome(member.Home, "id", "grant", "revoke", grantID, "--expect-subject", "someone-else")
		if err == nil {
			t.Fatalf("revoke for another subject succeeded: %s", out)
		}
		var refused cliErrorEnvelope
		if err := json.Unmarshal([]byte(out), &refused); err != nil || refused.Error.Code != releaseSubjectMismatch {
			t.Fatalf("refusal=%+v err=%v\n%s", refused, err, out)
		}
		if status := grantStatus(t, world, member.Home, grantID); status != "active" {
			t.Fatalf("grant status=%q after a refused revoke", status)
		}
	})

	t.Run("not found in the team", func(t *testing.T) {
		const missing = "00000000-0000-4000-8000-000000000002"
		out, err := world.runInIdentityHome(member.Home, "id", "grant", "revoke", missing)
		if err == nil {
			t.Fatalf("missing grant revoked: %s", out)
		}
		answer := decodeGrantRevoke(t, out)
		if answer.Error == nil || answer.Error.Code != string(grantNotFound) || answer.Release.Outcome != releaseRefused || answer.Release.Code != string(grantNotFound) || answer.Release.Target.GrantID != missing {
			t.Fatalf("refusal=%+v release=%+v", answer.Error, *answer.Release)
		}
	})

	t.Run("lost request stays unknown", func(t *testing.T) {
		grantID := mintGrantForRelease(t, world, member.Home)
		proxy := revocationDroppingProxy(t, world.Stack.ServerURL)
		out, err := world.runInIdentityHomeWithEnv(member.Home, []string{"AWEB_URL=" + proxy.URL}, "id", "grant", "revoke", grantID)
		if err == nil {
			t.Fatalf("an unconfirmed revoke succeeded: %s", out)
		}
		answer := decodeGrantRevoke(t, out)
		wantRetry := grantRevokeRetry(member.Home, grantID, world.TeamID)
		if answer.Error == nil || answer.Error.Code != "outcome_unknown" || answer.Release.Outcome != releaseUnknown || answer.Release.Code != "outcome_unknown" || answer.Release.NextStep != wantRetry {
			t.Fatalf("error=%+v release=%+v, want unknown with retry %q", answer.Error, *answer.Release, wantRetry)
		}
		if status := grantStatus(t, world, member.Home, grantID); status != "active" {
			t.Fatalf("grant status=%q, want the grant untouched", status)
		}
	})
}

// The real server commits the revoke and the fixture drops its reply: only the
// read-back of that grant's recorded revocation can confirm it.
func TestRealServerGrantRevokeLostReplyConfirmedByReadBack(t *testing.T) {
	world := newRealCommandWorldWithFaults(t, realCommandWorldFaults{LoseGrantRevokeResponse: true})
	member := world.addLocalMember(t, "resident")
	grantID := mintGrantForRelease(t, world, member.Home)
	out, err := world.runInIdentityHome(member.Home, "id", "grant", "revoke", grantID)
	if err != nil {
		t.Fatalf("lost reply with recorded revocation failed: %v\n%s", err, out)
	}
	answer := decodeGrantRevoke(t, out)
	if answer.Status != "revoked" || answer.RevokedAt == "" || answer.Release.Outcome != releaseConfirmed || answer.Release.Code != "" {
		t.Fatalf("answer=%+v release=%+v", answer, *answer.Release)
	}
	if status := grantStatus(t, world, member.Home, grantID); status != "revoked" {
		t.Fatalf("grant status=%q", status)
	}
}
