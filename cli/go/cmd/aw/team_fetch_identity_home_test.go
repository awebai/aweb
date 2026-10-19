package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
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

func TestFetchCertificateUsesSelectedKeyAndStoresOnlyAtSelectedRoot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	for _, source := range []string{"flag", "environment"} {
		t.Run(source, func(t *testing.T) {
			selected := filepath.Join(root, source, "principal")
			writeStandaloneSelectedIdentityForTest(t, selected)
			key, err := awid.LoadSigningKey(filepath.Join(selected, "signing.key"))
			if err != nil {
				t.Fatal(err)
			}
			pub := key.Public().(ed25519.PublicKey)
			did := awid.ComputeDIDKey(pub)
			_, controller, _ := awid.GenerateKeypair()
			cert, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{Team: "backend:acme.com", MemberDIDKey: did, Alias: "alice", IdentityScope: awid.IdentityModeLocal})
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := awid.EncodeTeamCertificateHeader(cert)
			var calls atomic.Int32
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/certificates/"+cert.CertificateID) {
					http.NotFound(w, r)
					return
				}
				fields := strings.Fields(r.Header.Get("Authorization"))
				if len(fields) != 3 {
					t.Error("missing selected-key signature")
					w.WriteHeader(401)
					return
				}
				signature, _ := base64.RawStdEncoding.DecodeString(fields[2])
				payload := r.Header.Get("X-AWEB-Timestamp") + "\n" + r.Method + "\n" + r.URL.Path
				if fields[1] != did || !ed25519.Verify(pub, []byte(payload), signature) {
					t.Error("certificate fetch used another identity key")
					w.WriteHeader(401)
					return
				}
				calls.Add(1)
				json.NewEncoder(w).Encode(map[string]any{"certificate": encoded})
			}))
			cwd := filepath.Join(root, source, "checkout")
			_, decoy, _ := awid.GenerateKeypair()
			writeSelectionFixtureForTest(t, cwd, testSelectionFixture{AwebURL: server.URL, TeamID: "decoy:example.test", Alias: "decoy", SigningKey: decoy})
			before := snapshotJoinFiles(t, cwd)
			args := []string{"id", "team", "fetch-cert", "--team", "backend", "--namespace", "acme.com", "--cert-id", cert.CertificateID, "--json"}
			env := append(testCommandEnv(filepath.Join(root, "user")), "AWEB_IDENTITY_HOME=", "AWID_REGISTRY_URL="+server.URL, "AWEB_URL=", "AW_NO_UPDATE_CHECK=1")
			if source == "flag" {
				args = append([]string{"--identity-home", selected}, args...)
			} else {
				env = append(env, "AWEB_IDENTITY_HOME="+selected)
			}
			command := exec.CommandContext(ctx, bin, args...)
			command.Dir, command.Env = cwd, env
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("fetch: %v\n%s", err, out)
			}
			installed, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(selected, cert.Team)
			if err != nil || installed.CertificateID != cert.CertificateID || calls.Load() != 1 {
				t.Fatalf("selected certificate installation: %v calls=%d", err, calls.Load())
			}
			state, err := awconfig.LoadTeamStateFromIdentityHome(selected)
			if err != nil || state.ActiveTeam != cert.Team {
				t.Fatalf("selected membership: %v", err)
			}
			if !reflect.DeepEqual(before, snapshotJoinFiles(t, cwd)) {
				t.Fatal("fetch wrote identity state into checkout")
			}
		})
	}
}
