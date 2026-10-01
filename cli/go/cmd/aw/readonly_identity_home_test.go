package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Exercise the production admission gate, identity selection and request auth,
// with both an empty cwd and a cwd containing an unrelated working identity.
func TestReadOnlyCommandsUseExternalIdentityHome(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	for _, kind := range []string{"native", "grant"} {
		for _, source := range []string{"flag", "environment"} {
			for _, cwdKind := range []string{"empty", "shadow"} {
				t.Run(kind+"/"+source+"/"+cwdKind, func(t *testing.T) {
					dir := filepath.Join(root, kind, source, cwdKind)
					instance := filepath.Join(dir, "instance")
					if err := os.MkdirAll(instance, 0700); err != nil {
						t.Fatal(err)
					}
					pub, key, err := awid.GenerateKeypair()
					if err != nil {
						t.Fatal(err)
					}
					teamID := "runtime:aweb.test"
					if kind == "grant" {
						teamID = "backend:acme.com"
					}
					var requests atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if r.Method != http.MethodGet {
							t.Errorf("unexpected mutation: %s %s", r.Method, r.URL)
							http.Error(w, "mutation", 500)
							return
						}
						if kind == "grant" {
							assertReadOnlyGrantRequest(t, r, pub)
						} else if !strings.HasPrefix(r.Header.Get("Authorization"), "DIDKey "+awid.ComputeDIDKey(pub)+" ") {
							t.Errorf("request not signed by external principal: %q", r.Header.Get("Authorization"))
						}
						switch r.URL.Path {
						case "/v1/instructions/active", "/v1/instructions/instructions-1":
							if kind == "native" {
								cert := requireCertificateAuthForTest(t, r)
								if cert.Team != teamID {
									t.Errorf("certificate team=%q", cert.Team)
								}
							}
							_ = json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "team_id": teamID, "version": 19, "document": map[string]string{"body_md": "External principal rules", "format": "markdown"}})
						case "/v1/agents":
							if kind != "grant" {
								t.Error("native roster switched away from AWID")
							}
							_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: teamID, Agents: []awid.AgentView{{Alias: "alice", DIDKey: awid.ComputeDIDKey(pub), DIDAW: "did:aw:alice", Address: "acme.com/alice", IdentityScope: "global"}}})
						case "/v1/namespaces/aweb.test/teams/runtime/certificates":
							if kind != "native" {
								t.Error("grant attempted AWID read")
							}
							_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []map[string]string{{"certificate_id": "cert-human", "team_id": teamID, "alias": "human", "member_did_key": awid.ComputeDIDKey(pub), "identity_scope": "local", "issued_at": "2026-10-01T00:00:00Z"}}})
						default:
							t.Errorf("unexpected path %s", r.URL)
							http.NotFound(w, r)
						}
					}))
					defer server.Close()
					identityHome := filepath.Join(dir, "principal", ".aw")
					if kind == "grant" {
						pub, _ = writeGrantHomeForTest(t, identityHome, server.URL)
						grant, err := awconfig.LoadGrantHome(identityHome)
						if err != nil {
							t.Fatal(err)
						}
						grant.Scopes = []string{"coord.read"}
						if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(identityHome), grant); err != nil {
							t.Fatal(err)
						}
					} else {
						writeMessagingPrincipalForTest(t, filepath.Dir(identityHome), server.URL, "principal", awid.ComputeDIDKey(pub), key)
						state, err := awconfig.LoadTeamStateFromIdentityHome(identityHome)
						if err != nil {
							t.Fatal(err)
						}
						state.Memberships[0].RegistryURL = server.URL
						if err := awconfig.SaveTeamState(filepath.Dir(identityHome), state); err != nil {
							t.Fatal(err)
						}
					}
					if cwdKind == "shadow" {
						writeTestConfig(t, instance, "http://127.0.0.1:1")
					}
					before := fileDigestsForTest(t, identityHome)
					shadowBefore := fileDigestsForTest(t, instance)
					for _, args := range [][]string{{"instructions", "show"}, {"instructions", "show", "instructions-1"}, {"id", "team", "members"}} {
						out, err := runReadOnlyBinary(ctx, bin, instance, filepath.Join(dir, "user"), identityHome, source, append(args, "--json")...)
						if err != nil {
							t.Errorf("authorized %v failed: %v\n%s", args, err, out)
							continue
						}
						if args[0] == "instructions" {
							if !strings.Contains(out, "External principal rules") {
								t.Errorf("wrong instructions: %s", out)
							}
						} else {
							var got struct {
								TeamID      string           `json:"team_id"`
								Members     []teamMemberItem `json:"members"`
								Source      string           `json:"source"`
								Limitations string           `json:"limitations"`
							}
							if err := json.Unmarshal([]byte(out), &got); err != nil {
								t.Fatal(err)
							}
							if got.TeamID != teamID || len(got.Members) != 1 {
								t.Fatalf("wrong roster: %s", out)
							}
							if kind == "grant" {
								if got.Source != "service-roster" || !strings.Contains(got.Limitations, "agents only") || !strings.Contains(got.Limitations, "no humans") || !strings.Contains(got.Limitations, "certificate") {
									t.Errorf("missing service limitations: %s", out)
								}
								if got.Members[0].Alias != "alice" || got.Members[0].MemberDIDAW != "did:aw:alice" || got.Members[0].CertificateID != "" || got.Members[0].IssuedAt != "" {
									t.Errorf("wrong service member: %s", out)
								}
							} else if got.Source != "" || got.Members[0].CertificateID != "cert-human" || got.Members[0].Alias != "human" {
								t.Errorf("native certificate output changed: %s", out)
							}
						}
					}
					if requests.Load() == 0 {
						t.Error("no authenticated read reached the selected service")
					}
					if !reflect.DeepEqual(before, fileDigestsForTest(t, identityHome)) {
						t.Error("read changed principal material")
					}
					if !reflect.DeepEqual(shadowBefore, fileDigestsForTest(t, instance)) {
						t.Error("read changed instance material")
					}
				})
			}
		}
	}
}

func runReadOnlyBinary(ctx context.Context, bin, cwd, userHome, identityHome, source string, args ...string) (string, error) {
	env := append(testCommandEnv(userHome), "AW_NO_UPDATE_CHECK=1", "AWEB_URL=", "AWID_REGISTRY_URL=", awconfig.IdentityHomeEnv+"=")
	if source == "flag" {
		args = append([]string{"--identity-home", identityHome}, args...)
	} else {
		env = append(env, awconfig.IdentityHomeEnv+"="+identityHome)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = cwd
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func assertReadOnlyGrantRequest(t *testing.T, r *http.Request, pub ed25519.PublicKey) {
	t.Helper()
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 4 || parts[0] != "AWEB-Grant" || parts[1] != "DIDKey" || parts[2] != awid.ComputeDIDKey(pub) {
		t.Errorf("wrong grant identity: %q", r.Header.Get("Authorization"))
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if err != nil {
		t.Error(err)
		return
	}
	sig, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		sig, err = base64.StdEncoding.DecodeString(parts[3])
	}
	if err != nil || !ed25519.Verify(pub, payload, sig) {
		t.Error("invalid grant signature")
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["path"] != r.URL.RequestURI() || fields["method"] != r.Method || fields["grant_id"] != "grant-777" || r.Header.Get("X-AWEB-Grant-ID") != "grant-777" {
		t.Errorf("grant envelope is not request-bound: %s", payload)
	}
	if r.Header.Get("X-AWID-Team-Certificate") != "" {
		t.Error("grant used root certificate authority")
	}
}

func TestReadOnlyGrantBoundaries(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		name         string
		args         []string
		want         string
		requests     int32
		status       int
		responseTeam string
		expired      bool
	}{
		{name: "roster-any-valid-grant", args: []string{"id", "team", "members"}, want: "agents only (no humans)", requests: 1},
		{name: "instructions-outside-scope", args: []string{"instructions", "show"}, want: "outside grant scope", requests: 1, status: 403},
		{name: "roster-revoked-grant", args: []string{"id", "team", "members"}, want: "identity grant rejected", requests: 1, status: 403},
		{name: "roster-server-failure", args: []string{"id", "team", "members"}, want: "roster unavailable", requests: 4, status: 503},
		{name: "roster-wrong-response-team", args: []string{"id", "team", "members"}, want: "roster response does not match", requests: 1, responseTeam: "other:acme.com"},
		{name: "roster-missing-response-team", args: []string{"id", "team", "members"}, want: "roster response does not match", requests: 1, responseTeam: "missing"},
		{name: "roster-expired", args: []string{"id", "team", "members"}, want: "expired", expired: true},
		{name: "instructions-expired", args: []string{"instructions", "show"}, want: "expired", expired: true},
		{name: "roster-team-id", args: []string{"id", "team", "members", "--team-id", "other:acme.com"}, want: "conflicts"},
		{name: "roster-team", args: []string{"id", "team", "members", "--team", "other"}, want: "conflicts"},
		{name: "roster-namespace", args: []string{"id", "team", "members", "--namespace", "other.test"}, want: "conflicts"},
		{name: "roster-conflicting-selectors", args: []string{"id", "team", "members", "--team-id", "backend:acme.com", "--team", "backend"}, want: "cannot be combined"},
		{name: "instructions-team", args: []string{"instructions", "show", "--team", "other:acme.com"}, want: "conflicts"},
		{name: "roster-registry", args: []string{"id", "team", "members", "--registry", "http://127.0.0.1:1"}, want: "--registry"},
		{name: "roster-revoked", args: []string{"id", "team", "members", "--include-revoked"}, want: "--include-revoked"},
		{name: "instructions-mutation-denied", args: []string{"instructions", "set", "--body", "replace"}, want: "not yet identity-home-aware"},
		{name: "roster-same-team", args: []string{"id", "team", "members", "--team-id", "backend:acme.com", "--json"}, want: "service-roster", requests: 1},
		{name: "roster-same-parts", args: []string{"id", "team", "members", "--team", "backend", "--namespace", "acme.com", "--json"}, want: "service-roster", requests: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(root, tc.name)
			instance := filepath.Join(dir, "instance")
			if err := os.MkdirAll(instance, 0700); err != nil {
				t.Fatal(err)
			}
			var pub ed25519.PublicKey
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				assertReadOnlyGrantRequest(t, r, pub)
				if tc.status != 0 {
					w.WriteHeader(tc.status)
					_ = json.NewEncoder(w).Encode(map[string]string{"detail": tc.want})
					return
				}
				if r.URL.Path != "/v1/agents" {
					t.Errorf("unexpected path: %s", r.URL)
					http.NotFound(w, r)
					return
				}
				team := "backend:acme.com"
				if tc.responseTeam != "" {
					team = tc.responseTeam
				}
				if team == "missing" {
					team = ""
				}
				_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: team, Agents: []awid.AgentView{{Alias: "alice", DIDKey: awid.ComputeDIDKey(pub), IdentityScope: "global"}}})
			}))
			defer server.Close()
			home := filepath.Join(dir, "grant")
			var grant *awconfig.GrantHome
			pub, grant = writeGrantHomeForTest(t, home, server.URL)
			// A messaging-only grant still has existing server roster authority;
			// its lack of coord.read must not become a new client roster denial.
			if tc.expired {
				grant.ExpiresAt = "2000-01-01T00:00:00Z"
				if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(home), grant); err != nil {
					t.Fatal(err)
				}
			}
			before := fileDigestsForTest(t, home)
			out, runErr := runReadOnlyBinary(ctx, bin, instance, filepath.Join(dir, "user"), home, "flag", tc.args...)
			wantSuccess := tc.status == 0 && tc.requests == 1 && tc.responseTeam == ""
			if (runErr == nil) != wantSuccess || !strings.Contains(out, tc.want) {
				t.Errorf("error=%v wantSuccess=%t want %q\n%s", runErr, wantSuccess, tc.want, out)
			}
			if got := calls.Load(); got != tc.requests {
				t.Errorf("requests=%d want %d", got, tc.requests)
			}
			if !reflect.DeepEqual(before, fileDigestsForTest(t, home)) {
				t.Error("changed grant material")
			}
			if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
				t.Errorf("read created cwd identity state: %v", err)
			}
		})
	}
}
