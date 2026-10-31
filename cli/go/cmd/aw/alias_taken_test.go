package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// A name another active member holds is refused in one plain sentence; --json
// keeps the alias_conflict envelope; the invite stays usable for a retry.
func TestAcceptInviteAliasTakenIsAPlainSentence(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "id team accept-invite", args: []string{"id", "team", "accept-invite"}},
		{name: "team join", args: []string{"team", "join", "--no-connect"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var aliasTaken atomic.Bool
			aliasTaken.Store(true)
			var memberDIDKey, memberStableID string
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
					if aliasTaken.Load() {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusConflict)
						_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": "alias_active", "message": "Alias already active in team"}})
						return
					}
					w.WriteHeader(http.StatusCreated)
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/encryption-key"):
					w.WriteHeader(http.StatusCreated)
				case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"address_id": "addr-alice", "domain": "acme.com", "name": "alice",
						"did_aw": memberStableID, "current_did_key": memberDIDKey,
						"reachability": "public", "created_at": "2026-04-06T00:00:00Z",
					})
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			tmp := t.TempDir()
			bin := filepath.Join(tmp, "aw")
			buildAwBinary(t, ctx, bin)

			_, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)
			memberPub, memberKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			memberDIDKey = awid.ComputeDIDKey(memberPub)
			memberStableID = awid.ComputeStableID(memberPub)
			if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
				DID: memberDIDKey, StableID: memberStableID, Address: "acme.com/alice",
				Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, CreatedAt: "2026-04-06T00:00:00Z",
			}); err != nil {
				t.Fatal(err)
			}
			if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
				t.Fatal(err)
			}
			env := append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
			run := func(args ...string) (string, error) {
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Env = env
				cmd.Dir = tmp
				out, err := cmd.CombinedOutput()
				return string(out), err
			}

			inviteOut, err := run("id", "team", "invite", "--team", "backend", "--namespace", "acme.com", "--member-global", "--json")
			if err != nil {
				t.Fatalf("team invite failed: %v\n%s", err, inviteOut)
			}
			var invite map[string]any
			if err := json.Unmarshal(extractJSON(t, []byte(inviteOut)), &invite); err != nil {
				t.Fatalf("invalid json: %v\n%s", err, inviteOut)
			}
			token, _ := invite["token"].(string)
			if token == "" {
				t.Fatal("invite token is empty")
			}
			accept := append(append([]string{}, tc.args...), token, "--global", "--no-address")

			const want = "The name alice is already taken in backend:acme.com. Pick another with --name. Your invite is still valid."
			out, err := run(accept...)
			if err == nil {
				t.Fatalf("accept succeeded despite the taken name:\n%s", out)
			}
			if strings.TrimSpace(out) != want {
				t.Fatalf("refusal text:\n got %q\nwant %q", strings.TrimSpace(out), want)
			}

			out, err = run(append(accept, "--json")...)
			if err == nil {
				t.Fatalf("accept --json succeeded despite the taken name:\n%s", out)
			}
			var envelope cliErrorEnvelope
			if err := json.Unmarshal(extractJSON(t, []byte(out)), &envelope); err != nil {
				t.Fatalf("invalid json envelope: %v\n%s", err, out)
			}
			if got := envelope.Error; got.Code != "alias_conflict" || got.HTTPStatus != http.StatusConflict || got.Detail != "Alias already active in team" || got.Message != want {
				t.Fatalf("envelope = %+v", got)
			}

			aliasTaken.Store(false)
			if out, err := run(accept...); err != nil {
				t.Fatalf("retry with the same invite failed: %v\n%s", err, out)
			}
		})
	}
}
