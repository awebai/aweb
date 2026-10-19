package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestTeamInviteActsFromExternalIdentityHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	pub, key, _ := ed25519.GenerateKey(nil)
	did := awid.ComputeDIDKey(pub)
	_, decoyKey, _ := ed25519.GenerateKey(nil)
	const team = "default:owner.aweb.ai"
	var creates atomic.Int32
	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/discovery":
			json.NewEncoder(w).Encode(map[string]string{"registry_url": serverURL, "aweb_url": serverURL, "onboarding_url": serverURL})
		case "/api/v1/spawn/create-invite":
			body, _ := io.ReadAll(r.Body)
			cert := requireCertificateAuthForTest(t, r)
			payload := requestSigningPayloadForTest(t, r, body)
			var envelope map[string]any
			json.Unmarshal(payload, &envelope)
			auth := strings.Fields(r.Header.Get("Authorization"))
			var sig []byte
			if len(auth) == 3 {
				sig, _ = base64.RawStdEncoding.DecodeString(auth[2])
			}
			hash := sha256.Sum256(body)
			boundRequestMismatch := envelope["v"] != nil && (envelope["method"] != r.Method || envelope["path"] != r.URL.RequestURI())
			if len(auth) != 3 || auth[1] != did || cert.MemberDIDKey != did || cert.Team != team || !ed25519.Verify(pub, payload, sig) || boundRequestMismatch || envelope["team_id"] != team || envelope["body_sha256"] != hex.EncodeToString(hash[:]) {
				t.Error("invite did not use the selected principal's signed team request")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			creates.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"invite_id": "invite-owned", "token": hostedJoinTokenForTest(t, "aw_inv_owned", serverURL)})
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = server.URL
	principal := filepath.Join(root, "principal")
	writeSelectionFixtureForTest(t, principal, testSelectionFixture{AwebURL: server.URL, RegistryURL: server.URL, TeamID: team, Alias: "owner", DID: did, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: key})
	decoy := filepath.Join(root, "decoy")
	writeSelectionFixtureForTest(t, decoy, testSelectionFixture{AwebURL: server.URL, RegistryURL: server.URL, TeamID: "other:decoy.test", Alias: "decoy", DID: awid.ComputeDIDKey(decoyKey.Public().(ed25519.PublicKey)), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: decoyKey})
	empty := filepath.Join(root, "empty-instance")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	before := snapshotJoinFiles(t, decoy)
	principalBefore := snapshotJoinFiles(t, principal)
	for _, cwd := range []string{empty, decoy} {
		for _, source := range []string{"flag", "environment"} {
			for _, surface := range [][]string{{"team", "invite"}, {"id", "team", "invite"}} {
				t.Run(filepath.Base(cwd)+"/"+source+"/"+strings.Join(surface, "-"), func(t *testing.T) {
					args := append(append([]string{}, surface...), "--json")
					env := append(testCommandEnv(filepath.Join(root, "user-home")), "USERPROFILE="+filepath.Join(root, "user-home"), "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AWID_REGISTRY_URL=", "AW_NO_UPDATE_CHECK=1")
					if source == "flag" {
						args = append([]string{"--identity-home", filepath.Join(principal, ".aw")}, args...)
					} else {
						env = append(env, "AWEB_IDENTITY_HOME="+filepath.Join(principal, ".aw"))
					}
					cmd := exec.CommandContext(ctx, bin, args...)
					cmd.Dir, cmd.Env = cwd, env
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("external invite: %v\n%s", err, out)
					}
					var result teamInviteOutput
					if err := json.Unmarshal(extractJSON(t, out), &result); err != nil || result.InviteID != "invite-owned" || result.Token == "" {
						t.Fatalf("invite result: %v %s", err, out)
					}
				})
			}
		}
	}
	if creates.Load() != 8 {
		t.Fatalf("invite requests=%d want8", creates.Load())
	}
	if !reflect.DeepEqual(before, snapshotJoinFiles(t, decoy)) || !reflect.DeepEqual(principalBefore, snapshotJoinFiles(t, principal)) {
		t.Fatal("invite changed principal or decoy files")
	}
	if _, err := os.Lstat(filepath.Join(empty, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("invite wrote instance identity: %v", err)
	}
}

func TestTeamInviteGrantKeepsServerRefusal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	var calls atomic.Int32
	var sessionPub ed25519.PublicKey
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/spawn/create-invite" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		payload, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		auth := strings.Fields(r.Header.Get("Authorization"))
		var sig []byte
		if len(auth) == 4 {
			sig, _ = base64.RawStdEncoding.DecodeString(auth[3])
		}
		var envelope map[string]any
		json.Unmarshal(payload, &envelope)
		hash := sha256.Sum256(body)
		if len(auth) != 4 || auth[0] != "AWEB-Grant" || auth[2] != awid.ComputeDIDKey(sessionPub) || !ed25519.Verify(sessionPub, payload, sig) || envelope["grant_id"] != "grant-777" || envelope["body_sha256"] != hex.EncodeToString(hash[:]) || r.Header.Get("X-AWID-Team-Certificate") != "" {
			t.Error("invite borrowed non-grant authority")
			w.WriteHeader(500)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"detail":{"code":"invite_grant_refused"}}`)
	}))
	grant := filepath.Join(root, "grant")
	sessionPub, _ = writeGrantHomeForTest(t, grant, server.URL)
	userHome := filepath.Join(root, "user-home")
	_, controller, _ := ed25519.GenerateKey(nil)
	// Even a controller available on this machine must not elevate a grant.
	writeTeamKeyForTest(t, userHome, "acme.com", "backend", controller)
	decoy := filepath.Join(root, "instance")
	_, key, _ := ed25519.GenerateKey(nil)
	writeSelectionFixtureForTest(t, decoy, testSelectionFixture{AwebURL: server.URL, TeamID: "other:decoy.test", Alias: "decoy", SigningKey: key})
	before := snapshotJoinFiles(t, decoy)
	for _, source := range []string{"flag", "environment"} {
		args := []string{"team", "invite", "--json"}
		env := append(testCommandEnv(userHome), "USERPROFILE="+userHome, "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AWID_REGISTRY_URL=", "AW_NO_UPDATE_CHECK=1")
		if source == "flag" {
			args = append([]string{"--identity-home", grant}, args...)
		} else {
			env = append(env, "AWEB_IDENTITY_HOME="+grant)
		}
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir, cmd.Env = decoy, env
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "invite_grant_refused") {
			t.Fatalf("grant invite must return server refusal (%s): %v\n%s", source, err, out)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("grant invite calls=%d want2", calls.Load())
	}
	if !reflect.DeepEqual(before, snapshotJoinFiles(t, decoy)) {
		t.Fatal("grant invite mutated CWD identity")
	}
	if _, err := os.Stat(filepath.Join(userHome, ".awid", "invites")); !os.IsNotExist(err) {
		t.Fatalf("grant minted a local-controller invite: %v", err)
	}
}

// A controller invite uses the selected team's controller, while global
// acceptance preserves the selected member key and publishes its own assertion.
func TestSelectedIdentityControllerInviteAndAcceptRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	for _, mode := range []string{"environment", "flag", "cwd"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(root, mode)
			userHome := filepath.Join(dir, "user")
			pubs := map[string]ed25519.PublicKey{}
			keys := map[string]ed25519.PrivateKey{}
			for _, name := range []string{"cwd", "environment", "flag"} {
				pubs[name], keys[name], _ = ed25519.GenerateKey(nil)
			}
			selectedPub, selectedKey := pubs[mode], keys[mode]
			did, stable := awid.ComputeDIDKey(selectedPub), awid.ComputeStableID(selectedPub)
			const team = "backend:acme.com"
			_, controller, _ := ed25519.GenerateKey(nil)
			writeTeamKeyForTest(t, userHome, "acme.com", "backend", controller)
			var registrations, assertions atomic.Int32
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/certificates"):
					var payload struct {
						Certificate string `json:"certificate"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					cert, err := awid.DecodeTeamCertificateHeader(payload.Certificate)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					if cert.MemberDIDKey != did || cert.MemberDIDAW != stable || cert.Team != team || awid.VerifyTeamCertificate(cert, controller.Public().(ed25519.PublicKey)) != nil {
						t.Error("accepted certificate did not bind the selected principal to the selected controller team")
						w.WriteHeader(400)
						return
					}
					registrations.Add(1)
					w.WriteHeader(http.StatusCreated)
				case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/encryption-key"):
					var assertion awid.EncryptionKeyAssertion
					if err := json.NewDecoder(r.Body).Decode(&assertion); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					if err := awid.VerifyEncryptionKeyAssertion(&assertion, did, stable, time.Now()); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					assertions.Add(1)
					w.WriteHeader(http.StatusCreated)
				default:
					http.NotFound(w, r)
				}
			}))
			for _, name := range []string{"cwd", "environment", "flag"} {
				teamID := "decoy:decoy.test"
				if name == mode {
					teamID = team
				}
				writeSelectionFixtureForTest(t, filepath.Join(dir, name), testSelectionFixture{AwebURL: server.URL, RegistryURL: server.URL, TeamID: teamID, Alias: "alice", DID: awid.ComputeDIDKey(pubs[name]), StableID: awid.ComputeStableID(pubs[name]), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, SigningKey: keys[name]})
			}
			cwd := filepath.Join(dir, "cwd")
			before := snapshotJoinFiles(t, cwd)
			selectedRoot := filepath.Join(dir, mode, ".aw")
			run := func(args ...string) []byte {
				env := append(testCommandEnv(userHome), "USERPROFILE="+userHome, "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AWID_REGISTRY_URL="+server.URL, "AW_NO_UPDATE_CHECK=1")
				if mode != "cwd" {
					env = append(env, "AWEB_IDENTITY_HOME="+filepath.Join(dir, "environment", ".aw"))
				}
				if mode == "flag" {
					args = append([]string{"--identity-home", selectedRoot}, args...)
				}
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir, cmd.Env = cwd, env
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v: %v\n%s", args, err, out)
				}
				return out
			}
			var invite teamInviteOutput
			if err := json.Unmarshal(extractJSON(t, run("team", "invite", "--member-global", "--json")), &invite); err != nil || invite.Token == "" {
				t.Fatalf("invite: %v %+v", err, invite)
			}
			run("id", "team", "accept-invite", invite.Token, "--name", "alice", "--global", "--no-address", "--json")
			if registrations.Load() != 1 || assertions.Load() != 1 {
				t.Fatalf("registrations=%d assertions=%d", registrations.Load(), assertions.Load())
			}
			keyAfter, err := awid.LoadSigningKey(filepath.Join(selectedRoot, "signing.key"))
			if err != nil || !reflect.DeepEqual(keyAfter, selectedKey) {
				t.Fatal("accept replaced selected member key")
			}
			if mode != "cwd" && !reflect.DeepEqual(before, snapshotJoinFiles(t, cwd)) {
				t.Fatal("controller invite/accept mutated decoy identity")
			}
		})
	}
}
