package main

import (
	"context"
	"encoding/json"
	"net/http"
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

// Real CLI processes and signing/verification, with an HTTP registry/coordination
// fixture. This is a composition regression, not a live BYOT rehearsal receipt.
func TestPreparedWorkerControllerFetchAndConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	worker := filepath.Join(root, "worker")
	owner := filepath.Join(root, "owner")
	for _, dir := range []string{worker, owner} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	selected := filepath.Join(root, "prepared")
	pub, controller, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, owner, "acme.com", "backend", controller)
	var stored guarded[*awid.TeamCertificate]
	var override guarded[*awid.TeamCertificate]
	var registryCalls, connectCalls atomic.Int32
	server := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/namespaces/acme.com/teams/backend/certificates":
			registryCalls.Add(1)
			var body struct {
				Certificate string `json:"certificate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			cert, err := awid.DecodeTeamCertificateHeader(body.Certificate)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if err := awid.VerifyTeamCertificate(cert, pub); err != nil {
				t.Error(err)
				w.WriteHeader(403)
				return
			}
			stored.set(cert)
			w.WriteHeader(201)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/certificates/"):
			registryCalls.Add(1)
			cert := stored.get()
			if forced := override.get(); forced != nil {
				cert = forced
			}
			if cert == nil {
				w.WriteHeader(404)
				return
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"certificate": encoded})
		case r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"onboarding_url": origin, "aweb_url": origin, "registry_url": origin})
		case r.Method == "POST" && r.URL.Path == "/v1/connect":
			cert := requireCertificateAuthForTest(t, r)
			registered := stored.get()
			if registered == nil || cert.CertificateID != registered.CertificateID || awid.VerifyTeamCertificate(cert, pub) != nil {
				t.Error("connect did not carry the controller-issued certificate")
				w.WriteHeader(403)
				return
			}
			connectCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": cert.Team, "alias": "worker", "agent_id": "agent-worker", "workspace_id": "workspace-worker", "team_did_key": awid.ComputeDIDKey(pub)})
		case r.Method == "PUT" && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-worker", "backend:acme.com", "worker")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	})
	run := func(dir string, args ...string) ([]byte, error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = dir
		cmd.Env = append(testCommandEnv(dir), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1", "AWID_REGISTRY_URL="+server.URL, "AWEB_URL=")
		return cmd.CombinedOutput()
	}
	out, err := run(worker, "--identity-home", selected, "id", "team", "request", "--create-local-key", "--team", "backend:acme.com", "--name", "worker", "--json")
	if err != nil {
		t.Fatalf("prepare: %v %s", err, out)
	}
	var request map[string]any
	if err := json.Unmarshal(out, &request); err != nil {
		t.Fatal(err)
	}
	before := snapshotPreparationTree(t, selected)
	out, err = run(worker, "--identity-home", selected, "id", "show", "--json")
	if err == nil || !strings.Contains(string(out), "selected identity home") {
		t.Fatalf("other command bypassed selection: %v %s", err, out)
	}
	if !reflect.DeepEqual(before, snapshotPreparationTree(t, selected)) || registryCalls.Load() != 0 {
		t.Fatal("preparation/selection mutated or contacted registry")
	}
	out, err = run(owner, "id", "team", "add-member", "--team", "backend", "--namespace", "acme.com", "--did", request["did_key"].(string), "--name", "worker", "--local", "--json")
	if err != nil {
		t.Fatalf("controller add-member: %v %s", err, out)
	}
	cert := stored.get()
	if cert == nil || cert.MemberDIDKey != request["did_key"] {
		t.Fatal("controller registered wrong subject")
	}
	fetch := []string{"--identity-home", selected, "id", "team", "fetch-cert", "--team", "backend", "--namespace", "acme.com", "--cert-id", cert.CertificateID, "--json"}
	for _, state := range []string{"malformed key", "stray teams"} {
		t.Run(state, func(t *testing.T) {
			keyPath := filepath.Join(selected, "signing.key")
			original, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if state == "malformed key" {
				if err := os.WriteFile(keyPath, []byte("malformed"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(filepath.Join(selected, "teams.yaml"), []byte("invalid: ["), 0600); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := snapshotPreparationTree(t, selected)
			calls := registryCalls.Load()
			out, err := run(worker, fetch...)
			if err == nil || !strings.Contains(string(out), "selected identity home") {
				t.Fatalf("partial selection: %v %s", err, out)
			}
			if registryCalls.Load() != calls || !reflect.DeepEqual(snapshot, snapshotPreparationTree(t, selected)) {
				t.Fatal("partial target fetched or mutated")
			}
			if state == "malformed key" {
				if err := os.WriteFile(keyPath, original, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(filepath.Join(selected, "teams.yaml")); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	other, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{Team: cert.Team, MemberDIDKey: awid.ComputeDIDKey(other), Alias: "worker", IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	override.set(wrong)
	wrongFetch := append([]string{}, fetch...)
	wrongFetch[len(wrongFetch)-2] = wrong.CertificateID
	out, err = run(worker, wrongFetch...)
	if err == nil || !strings.Contains(string(out), "member_did_key") {
		t.Fatalf("wrong subject accepted: %v %s", err, out)
	}
	if !reflect.DeepEqual(before, snapshotPreparationTree(t, selected)) {
		t.Fatal("wrong certificate mutated prepared root")
	}
	override.set(nil)
	out, err = run(worker, fetch...)
	if err != nil {
		t.Fatalf("fetch: %v %s", err, out)
	}
	installed, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(selected, cert.Team)
	if err != nil || installed.CertificateID != cert.CertificateID {
		t.Fatalf("installed: %v", err)
	}
	out, err = run(worker, "--identity-home", selected, "workspace", "connect", "--service", server.URL, "--json")
	if err != nil {
		t.Fatalf("connect: %v %s", err, out)
	}
	if connectCalls.Load() == 0 {
		t.Fatal("never connected")
	}
	if _, err := os.Stat(filepath.Join(worker, ".aw", "signing.key")); !os.IsNotExist(err) {
		t.Fatal("created a second key in worker checkout")
	}
}
