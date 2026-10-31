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

// writeAliasConflict answers a registry or server request with the coded 409
// a name conflict carries.
func writeAliasConflict(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": code, "message": message}})
}

// A connect the server refuses over the certificate's name says what the
// situation is: the certificate already carries the name, so --name cannot
// fix it on this workspace.
func TestConnectNameRefusalsArePlainSentences(t *testing.T) {
	for _, tc := range []struct {
		code, message, want, envelopeCode string
	}{
		{
			code:         "alias_active",
			message:      "alias 'alice' is already in use by another active agent in team default:local",
			want:         "The name alice is already used by another agent in default:local. This workspace's certificate is for that name, so ask a team admin to free the name, or join again with a new invite and another --name.",
			envelopeCode: "alias_conflict",
		},
		{
			code:         "alias_mismatch",
			message:      "cert claims alias 'alice' but did_key is already bound to alias 'bob' in team default:local",
			want:         "This agent is already a member of default:local under another name, so its certificate for the name alice cannot connect. Connect with its certificate for that other name, or ask a team admin to retire that membership first.",
			envelopeCode: "http_error",
		},
	} {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/connect" {
					writeAliasConflict(w, tc.code, tc.message)
					return
				}
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}))
			_, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			memberPub, memberKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team: "default:local", MemberDIDKey: awid.ComputeDIDKey(memberPub), Alias: "alice", IdentityScope: awid.IdentityModeLocal,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, err = postConnect(ctx, server.URL, memberKey, cert, connectRequest{})
			if err == nil {
				t.Fatal("connect succeeded despite the refusal")
			}
			if err.Error() != tc.want {
				t.Fatalf("refusal text:\n got %q\nwant %q", err.Error(), tc.want)
			}
			if got := errorEnvelope(err, err.Error()).Error; got.Code != tc.envelopeCode || got.HTTPStatus != http.StatusConflict || got.Detail != tc.message {
				t.Fatalf("envelope = %+v", got)
			}
		})
	}
}

// aw init's local and guided paths register the first member themselves; a
// name the team already holds is refused in a sentence naming --name.
func TestLocalTeamBootstrapNameTakenIsAPlainSentence(t *testing.T) {
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "controller_did": body["controller_did"], "created_at": "2026-04-07T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "default:acme.com", "domain": "acme.com", "name": "default", "team_did_key": body["team_did_key"], "created_at": "2026-04-07T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/default/certificates":
			writeAliasConflict(w, "alias_active", "Alias already active in team")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Setenv("HOME", t.TempDir())
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.SetFallbackRegistryURL(server.URL); err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = bootstrapLocalTeamMemberWithScope(ctx, registry, "", "acme.com", "default", "", controllerKey, memberKey, "", "", "alice", awid.IdentityModeLocal)
	if err == nil {
		t.Fatal("bootstrap succeeded despite the taken name")
	}
	const want = "The name alice is already taken in default:acme.com. Pick another with --name."
	if err.Error() != want {
		t.Fatalf("refusal text:\n got %q\nwant %q", err.Error(), want)
	}
	if got := errorEnvelope(err, err.Error()).Error; got.Code != "alias_conflict" || got.HTTPStatus != http.StatusConflict || got.Detail != "Alias already active in team" {
		t.Fatalf("envelope = %+v", got)
	}
}

// aw team admin create registers its first agent; a name the team already
// holds is refused in a sentence naming --first-agent-name.
func TestTeamAdminCreateFirstAgentNameTakenIsAPlainSentence(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Chdir(root)
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), memberKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: memberDID, StableID: "did:aw:zSelf", Address: "acme.com/alice", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("acme.com", controllerKey); err != nil {
		t.Fatal(err)
	}
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "controller_did": body["controller_did"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "name": "alice", "did_aw": "did:aw:zSelf", "current_did_key": memberDID})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:acme.com", "domain": "acme.com", "name": body["name"], "team_did_key": body["team_did_key"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/eng/certificates":
			writeAliasConflict(w, "alias_active", "Alias already active in team")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	teamHumanCreateFirstGlobal = true
	initAwebURL = server.URL

	err = runTeamHumanCreate(nil, []string{"Eng"})
	if err == nil {
		t.Fatal("team admin create succeeded despite the taken name")
	}
	const want = "The name eng is already taken in eng:acme.com. Pick another with --first-agent-name."
	if err.Error() != want {
		t.Fatalf("refusal text:\n got %q\nwant %q", err.Error(), want)
	}
	if got := errorEnvelope(err, err.Error()).Error; got.Code != "alias_conflict" || got.HTTPStatus != http.StatusConflict || got.Detail != "Alias already active in team" {
		t.Fatalf("envelope = %+v", got)
	}
}
