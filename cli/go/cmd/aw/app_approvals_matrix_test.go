package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestAppApprovalBinaryMintAndDispatchMatrix(t *testing.T) {
	fixtures, err := filepath.Abs("../../internal/appmanifest/testdata")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, team := range []string{"backend:acme.com", "personal:app.aweb.ai"} {
		for _, mode := range []string{awid.IdentityModeLocal, awid.IdentityModeGlobal} {
			t.Run(team+"/"+mode, func(t *testing.T) {
				f := setupAppCustodyFixtureForTeam(t, nil, team, mode)
				var served atomic.Value
				f.app.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/.well-known/aweb-app.json" {
						w.Write(served.Load().([]byte))
						return
					}
					f.app.handle(w, r)
				})
				cert, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(f.residentHome, team)
				if err != nil {
					t.Fatal(err)
				}
				var mu sync.Mutex
				keys := map[string]string{}
				var mintRequests atomic.Int32
				coordination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "POST" || r.URL.Path != "/v1/identity-grants" {
						http.NotFound(w, r)
						return
					}
					data, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(data))
					certificate, certErr := awid.DecodeTeamCertificateHeader(r.Header.Get("X-AWID-Team-Certificate"))
					if certErr != nil || awid.VerifyTeamCertificate(certificate, f.app.teamPub) != nil || certificate.Team != team || certificate.MemberDIDKey != f.residentDID {
						t.Error("mint certificate validation failed")
						http.Error(w, "auth", 401)
						return
					}
					var request struct {
						GrantDIDKey string   `json:"grant_did_key"`
						Scopes      []string `json:"scopes"`
					}
					if err := json.Unmarshal(data, &request); err != nil {
						t.Error(err)
						return
					}
					id, _ := awid.GenerateUUID4()
					mu.Lock()
					keys[id] = request.GrantDIDKey
					mu.Unlock()
					mintRequests.Add(1)
					json.NewEncoder(w).Encode(map[string]any{"grant_id": id, "team_id": team, "subject_did_aw": "did:aw:alice", "subject_alias": "alice", "grant_did_key": request.GrantDIDKey, "scopes": request.Scopes, "issued_at": time.Now().UTC().Format(time.RFC3339), "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
				}))
				defer coordination.Close()
				f.svc.grantStatus = func(_ context.Context, id string) (custodyGrantStatus, error) {
					mu.Lock()
					key := keys[id]
					mu.Unlock()
					return custodyGrantStatus{Active: key != "", Status: "active", EffectiveStatus: "active", TeamID: team, GrantDIDKey: key, Scopes: []string{"mail.read"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
				}
				writeSelectionFixtureForTest(t, filepath.Dir(f.residentHome), testSelectionFixture{AwebURL: coordination.URL, TeamID: team, Alias: "alice", WorkspaceID: "fixture", DID: f.residentDID, StableID: "did:aw:alice", Address: "acme.com/alice", Custody: awid.CustodySelf, IdentityScope: mode, SigningKey: f.svc.signingKey})
				if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(f.residentHome, team, cert); err != nil {
					t.Fatal(err)
				}
				home, err := filepath.EvalSymlinks(f.residentHome)
				if err != nil {
					t.Fatal(err)
				}
				instance := t.TempDir()
				invoke := func(selected, want string, args ...string) []byte {
					t.Helper()
					cmd := exec.CommandContext(ctx, bin, append([]string{"--identity-home", selected, "--json"}, args...)...)
					cmd.Dir = instance
					cmd.Env = append(os.Environ(), "AW_NO_UPDATE_CHECK=1")
					out, err := cmd.CombinedOutput()
					if want == "" && err != nil {
						t.Fatalf("%v: %v %s", args, err, out)
					}
					if want != "" && (err == nil || !strings.Contains(string(out), want)) {
						t.Fatalf("%v expected %s: %v %s", args, want, err, out)
					}
					return out
				}
				mint := func(extra ...string) (string, grantMintOutput) {
					t.Helper()
					outDir := filepath.Join(instance, fmt.Sprintf("grant-%d", mintRequests.Load()))
					args := []string{"id", "grant", "mint", "--scope", "mail.read", "--out", outDir, "--custody-socket", f.grant.Custody.SocketPath}
					var output grantMintOutput
					if err := json.Unmarshal(invoke(home, "", append(args, extra...)...), &output); err != nil {
						t.Fatal(err)
					}
					return outDir, output
				}
				emptyHome, emptyOutput := mint()
				if emptyOutput.Apps == nil || len(emptyOutput.Apps) != 0 {
					t.Fatal("empty catalog silently widened")
				}
				for _, name := range []string{"folio", "library"} {
					raw, err := os.ReadFile(filepath.Join(fixtures, name+"-deployed.json"))
					if err != nil {
						t.Fatal(err)
					}
					served.Store(raw)
					invoke(home, "", "plugin", "install", f.app.server.URL, "--dev-origin", f.app.server.URL)
				}
				// Empty old grants do not gain authority when the resident later installs.
				invoke(emptyHome, "app_tool_denied", "folio", "list")
				worker, output := mint()
				if len(output.Apps) != 2 || output.Apps[0].AppID != "folio" || output.Apps[1].AppID != "library" {
					t.Fatalf("mint inventory: %+v", output.Apps)
				}
				snap, err := loadGrantAppToolsSnapshot(home, output.GrantID)
				if err != nil {
					t.Fatal(err)
				}
				actual, _ := json.Marshal(grantAppInventory(snap.Apps))
				reported, _ := json.Marshal(output.Apps)
				if !bytes.Equal(actual, reported) {
					t.Fatal("mint output differs from persisted authority")
				}
				calls := [][]string{
					{"folio", "create", "--slug", "fixture", "--title", "Fixture", "--body", "Synthetic document"},
					{"folio", "show", "--slug", "fixture"},
					{"folio", "append", "--slug", "fixture", "--body", "Synthetic next version"},
					{"folio", "versions", "--slug", "fixture"},
					{"folio", "present", "--slug", "fixture"},
					{"library", "create-shelf-profile", "--files", "[]", "--tags", "[]"},
					{"library", "shelf"},
				}
				for _, selected := range []string{home, worker} {
					for _, args := range calls {
						invoke(selected, "", args...)
					}
				}
				// Explicit released selection is not unioned with both approved apps.
				catalogBefore, _ := os.ReadFile(appApprovalsPath(home))
				narrow, narrowOutput := mint("--app-tool", "folio:show")
				if len(narrowOutput.Apps) != 1 || len(narrowOutput.Apps[0].Tools) != 1 {
					t.Fatal("explicit legacy mint widened")
				}
				invoke(narrow, "", "folio", "show", "--slug", "fixture")
				invoke(narrow, "app_tool_denied", "library", "shelf")
				catalogAfter, _ := os.ReadFile(appApprovalsPath(home))
				if !bytes.Equal(catalogBefore, catalogAfter) {
					t.Fatal("explicit mint persisted approval")
				}
				before := mintRequests.Load()
				for i, value := range []string{"", "missing:show", "folio:nope"} {
					invoke(home, "app-tool", "id", "grant", "mint", "--scope", "mail.read", "--out", filepath.Join(instance, fmt.Sprintf("invalid-%d", i)), "--app-tool", value)
				}
				if mintRequests.Load() != before {
					t.Fatal("invalid selection reached mint server")
				}
				// Worker edits cannot redirect a snapshotted tool to another origin/path.
				dir, _ := pluginDir()
				path := manifestPluginManifestPath(dir, "folio")
				raw, _ := os.ReadFile(path)
				var manifest map[string]any
				if err := json.Unmarshal(raw, &manifest); err != nil {
					t.Fatal(err)
				}
				manifest["app"].(map[string]any)["origin"] = "http://127.0.0.1:1"
				changed, _ := json.Marshal(manifest)
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
				invoke(worker, "", "folio", "show", "--slug", "fixture")
				for _, tc := range []struct {
					code  string
					bytes []byte
				}{
					{"app_origin_mismatch", changed},
					{"app_manifest_invalid", []byte(`{"invalid":true}`)},
					{"app_manifest_mismatch", bytes.Replace(raw, []byte(`"id":"folio"`), []byte(`"id":"otherapp"`), 1)},
					{"app_missing", nil},
				} {
					// Stored JSON is compact because --dev-origin re-encodes it.
					if tc.bytes == nil {
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(path, tc.bytes, 0600); err != nil {
						t.Fatal(err)
					}
					narrowed, receipt := mint()
					if len(receipt.Apps) != 1 || receipt.Apps[0].AppID != "library" || len(receipt.SkippedApps) != 1 || receipt.SkippedApps[0].AppID != "folio" || receipt.SkippedApps[0].Code != tc.code {
						t.Fatalf("catalog mint skip %s: %+v", tc.code, receipt)
					}
					invoke(narrowed, "", "library", "shelf")
				}

				if _, err := os.Stat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
					t.Fatal("instance fallback")
				}
			})
		}
	}
}
