package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The fixture uses the shared profile's domain bytes and canonicalizer, with
// disposable issuer keys. It constructs signed data, never a production verifier.
func signedRefreshFixture(t *testing.T, body map[string]any, seed byte) map[string]any {
	t.Helper()
	profile, err := os.ReadFile(filepath.Join(approvalServiceFixtureRoot(t), "src", "approval_service", "data", "format-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var format struct {
		Domains map[string]string `json:"x-domains"`
	}
	if err := json.Unmarshal(profile, &format); err != nil {
		t.Fatal(err)
	}
	domain, ok := format.Domains["binding"]
	if !ok || domain == "" {
		t.Fatal("shared binding domain missing")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	t.Cleanup(func() { clear(key) })
	body["issuer"] = awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	raw, err := proof.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(domain), raw...)
	signature := ed25519.Sign(key, message)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), message, signature) {
		t.Fatal("fixture signature invalid")
	}
	return map[string]any{"binding": body, "signature": base64.RawURLEncoding.EncodeToString(signature)}
}

func changedRefreshFixtures(t *testing.T, h *humanParticipation, origin string) (map[string]any, map[string]any) {
	t.Helper()
	_, template := refreshBindingFixture(t)
	raw, err := proof.Canonical(template["binding"])
	if err != nil {
		t.Fatal(err)
	}
	body, err := proof.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	body["person"], body["identity_key"], body["organisation"] = h.record.StableID, h.record.DIDKey, h.record.Domain
	body["origin"] = origin
	old := signedRefreshFixture(t, body, 9)
	raw, err = proof.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	newBody, err := proof.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	newBody["certificate"] = "sha256:" + strings.Repeat("b", 64)
	updated := signedRefreshFixture(t, newBody, 10)
	if sameEnrollmentValue(old, updated) || sameEnrollmentValue(old["binding"], updated["binding"]) {
		t.Fatal("fixture did not change signed binding")
	}
	return old, updated
}

type refreshCommandScenario string

const (
	refreshCommandSuccess             refreshCommandScenario = "success"
	refreshCommandTransientReplay     refreshCommandScenario = "transient replay"
	refreshCommandInvalidAnswerReplay refreshCommandScenario = "invalid answer replay"
	refreshCommandDefinitiveRecovery  refreshCommandScenario = "definitive recovery"
	refreshCommandSavedLiveReplay     refreshCommandScenario = "saved live replay"
	refreshCommandCorruptRetained     refreshCommandScenario = "corrupt retained"
)

type refreshCommandPeer struct {
	t                         *testing.T
	human                     *humanParticipation
	scenario                  refreshCommandScenario
	pending                   string
	packet                    []byte
	original, updated         map[string]any
	mutex                     sync.Mutex
	serviceCalls, holderCalls int
	sent                      [][]byte
}

func (state *refreshCommandPeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, h := state.t, state.human
	pending, scenario := state.pending, state.scenario
	packet, old, updated := state.packet, state.original, state.updated
	state.mutex.Lock()
	defer state.mutex.Unlock()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
		w.WriteHeader(500)
		return
	}
	if r.Method != http.MethodPost {
		t.Errorf("unexpected method %s", r.Method)
		w.WriteHeader(405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/v1/enrollments/"+h.record.StableID+"/refresh-binding" {
		state.holderCalls++
		payload, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		auth := strings.Fields(r.Header.Get("Authorization"))
		if err != nil || len(auth) != 3 {
			t.Error("holder request missing proof")
			w.WriteHeader(401)
			return
		}
		status, err := awid.VerifySignedPayload(string(payload), auth[2], h.record.DIDKey, "")
		if err != nil || status != awid.Verified {
			t.Errorf("invalid holder proof: %v", err)
			w.WriteHeader(401)
			return
		}
		if _, err := os.Stat(pending); !os.IsNotExist(err) {
			t.Errorf("holder called while packet exists: %v", err)
		}
		if _, err := w.Write(packet); err != nil {
			t.Error(err)
		}
		return
	}
	if r.URL.Path != "/v1/enrollment-bindings/refresh" {
		t.Errorf("unexpected path %s", r.URL.Path)
		w.WriteHeader(404)
		return
	}
	state.serviceCalls++
	state.sent = append(state.sent, append([]byte(nil), raw...))
	body, err := proof.Parse(raw)
	if err != nil {
		t.Error(err)
		w.WriteHeader(400)
		return
	}
	requester := map[string]any{"kind": "identity", "id": h.record.StableID, "key": h.record.DIDKey}
	origin := "https://" + r.Host
	if _, err := proof.CheckHTTP(r.Header.Get("Authorization"), raw, proof.HTTPInput{Requester: requester, Origin: origin, Method: r.Method, Path: r.URL.Path, Purpose: "binding_refresh", Now: time.Now().Unix()}); err != nil {
		t.Errorf("invalid shared service proof: %v", err)
		w.WriteHeader(401)
		return
	}
	retained, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(retained, packet) {
		t.Errorf("send before exact retention: %v", err)
	}
	info, err := os.Stat(pending)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("pending mode: %v", err)
	}
	current, err := loadHumanApprovalBinding(h.dir)
	want := old
	if scenario == refreshCommandSavedLiveReplay {
		want = updated
	}
	if err != nil || !sameEnrollmentValue(current, want) {
		t.Errorf("live changed before confirmation: %v", err)
	}
	if state.serviceCalls == 1 && scenario == refreshCommandTransientReplay {
		w.WriteHeader(503)
		if _, err := w.Write([]byte(`{"version":1,"error":{"code":"status_unavailable","message":"Retry later."}}`)); err != nil {
			t.Error(err)
		}
		return
	}
	if state.serviceCalls == 1 && scenario == refreshCommandDefinitiveRecovery {
		w.WriteHeader(409)
		if _, err := w.Write([]byte(`{"version":1,"error":{"code":"binding_refresh_previous_changed","message":"Use your last successful live binding."}}`)); err != nil {
			t.Error(err)
		}
		return
	}
	digest, err := proof.Commitment("binding_commitment", body["binding"])
	if err != nil {
		t.Error(err)
		w.WriteHeader(500)
		return
	}
	if state.serviceCalls == 1 && scenario == refreshCommandInvalidAnswerReplay {
		digest = "sha256:" + strings.Repeat("0", 64)
	}
	if err := json.NewEncoder(w).Encode(map[string]any{"version": 1, "person": h.record.StableID, "state": "active", "binding_commitment": digest}); err != nil {
		t.Error(err)
	}
}

// Private HTTPS peers exercise the command, encrypted-file signer, durable
// files and shared request/answer owners. They do not prove registry admission
// or the holder/service database rules; those remain native journey coverage.
func TestHumanBindingRefreshCommandRecovery(t *testing.T) {
	if os.Getenv("AW_TEST_REFRESH_COMMAND_CHILD") != "1" {
		child := exec.Command(os.Args[0], "-test.run=^TestHumanBindingRefreshCommandRecovery$", "-test.v")
		child.Env = append(os.Environ(), "AW_TEST_REFRESH_COMMAND_CHILD=1", "GODEBUG=x509usefallbackroots=1", "AW_TEST_APPROVAL_MODULE_ROOT="+approvalServiceFixtureRoot(t))
		output, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("command regression: %v\n%s", err, output)
		}
		return
	}
	root := httptest.NewTLSServer(http.NotFoundHandler())
	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate())
	x509.SetFallbackRoots(roots)
	root.Close()
	for _, scenario := range []refreshCommandScenario{refreshCommandSuccess, refreshCommandTransientReplay, refreshCommandInvalidAnswerReplay, refreshCommandDefinitiveRecovery, refreshCommandSavedLiveReplay, refreshCommandCorruptRetained} {
		t.Run(string(scenario), func(t *testing.T) {
			h, _, _ := commandUnlockFixture(t, humanPassphrase)
			oldHuman, oldIssuer := activeHuman, humanRefreshIssuer
			activeHuman = h
			t.Cleanup(func() { activeHuman, humanRefreshIssuer = oldHuman, oldIssuer })
			var packet []byte
			var old, updated map[string]any
			var replacementCalls int
			pending := filepath.Join(h.dir, "approval-binding-refresh.json")
			live := filepath.Join(h.dir, "approval-live-binding.json")
			exchange := &refreshCommandPeer{t: t, human: h, scenario: scenario, pending: pending}
			peer := httptest.NewTLSServer(exchange)
			defer peer.Close()
			old, updated = changedRefreshFixtures(t, h, peer.URL)
			packet = refreshPacketBetween(t, h, old, updated)
			exchange.packet, exchange.original, exchange.updated = packet, old, updated
			for _, name := range []string{"approval-binding.json", "approval-live-binding.json"} {
				if err := saveHumanEnrollment(filepath.Join(h.dir, name), old); err != nil {
					t.Fatal(err)
				}
			}
			history := map[string][]byte{}
			for _, name := range []string{"approval-evidence.json", "enrollment-session.json"} {
				if err := os.WriteFile(filepath.Join(h.dir, name), []byte("immutable history\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"approval-binding.json", "approval-evidence.json", "enrollment-session.json"} {
				raw, err := os.ReadFile(filepath.Join(h.dir, name))
				if err != nil {
					t.Fatal(err)
				}
				history[name] = raw
			}
			if scenario == refreshCommandSavedLiveReplay {
				if err := saveHumanEnrollment(live, updated); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(pending, packet, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == refreshCommandCorruptRetained {
				if err := os.WriteFile(pending, []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			humanRefreshIssuer = peer.URL
			run := func() error {
				// Each retry is a new command with a new encrypted-key unlock. Cobra's
				// real finalizer wipes the preceding command's signing session.
				fresh, err := loadHumanParticipationState(h.record.StableID, h.record.Domain, humanBackupFile{h.record.StableID, filepath.Join(os.Getenv("HOME"), "backup.pbes2")}, func(string) ([]byte, error) { return []byte(humanPassphrase), nil }, func() error { return nil }, true)
				if err != nil {
					return err
				}
				activeHuman = fresh
				defer fresh.close()
				cmd := &cobra.Command{Use: "refresh-binding", RunE: runIDHumanRefreshBinding}
				cmd.SetOut(io.Discard)
				cmd.SetErr(io.Discard)
				cmd.SetArgs([]string{})
				return cmd.Execute()
			}
			err := run()
			if scenario == refreshCommandCorruptRetained {
				if err == nil || !strings.Contains(err.Error(), pending) || strings.Contains(err.Error(), "holder returned") {
					t.Fatalf("wrong retained-source advice: %v", err)
				}
				if exchange.holderCalls != 0 || exchange.serviceCalls != 0 {
					t.Fatal("corrupt retained packet exchange.sent a request")
				}
				return
			}
			if scenario == refreshCommandTransientReplay || scenario == refreshCommandInvalidAnswerReplay || scenario == refreshCommandDefinitiveRecovery {
				if err == nil {
					t.Fatal("unconfirmed answer reported success")
				}
				retained, readErr := os.ReadFile(pending)
				if readErr != nil || !bytes.Equal(retained, packet) {
					t.Fatalf("lost uncertain/refused packet: %v", readErr)
				}
				current, readErr := loadHumanApprovalBinding(h.dir)
				if readErr != nil || !sameEnrollmentValue(current, old) {
					t.Fatal("unconfirmed answer changed live binding")
				}
				replacement := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					replacementCalls++
					if _, err := w.Write(packet); err != nil {
						t.Error(err)
					}
				}))
				defer replacement.Close()
				humanRefreshIssuer = replacement.URL
				if scenario == refreshCommandDefinitiveRecovery {
					if !strings.Contains(err.Error(), pending) || !strings.Contains(err.Error(), "--issuer") || strings.Contains(err.Error(), "Keep the retained packet and retry") {
						t.Fatalf("permanent replay trap has no recovery: %v", err)
					}
					if err := os.Remove(pending); err != nil {
						t.Fatal(err)
					}
				}
				if err := run(); err != nil {
					t.Fatal(err)
				}
				if scenario == refreshCommandDefinitiveRecovery && replacementCalls != 1 {
					t.Fatal("explicit issuer was not used after discarding the definitively refused packet")
				}
				if scenario != refreshCommandDefinitiveRecovery && replacementCalls != 0 {
					t.Fatal("issuer flag replaced uncertain operation")
				}
				if len(exchange.sent) != 2 || !bytes.Equal(exchange.sent[0], exchange.sent[1]) {
					t.Fatal("replay changed exact submitted packet")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			current, err := loadHumanApprovalBinding(h.dir)
			if err != nil || !sameEnrollmentValue(current, updated) || sameEnrollmentValue(current, old) {
				t.Fatal("confirmed changed binding was not saved")
			}
			if _, err := os.Stat(pending); !os.IsNotExist(err) {
				t.Fatalf("confirmed packet retained: %v", err)
			}
			if scenario == refreshCommandSavedLiveReplay && exchange.holderCalls != 0 {
				t.Fatal("cleanup replay requested another holder packet")
			}
			for name, before := range history {
				after, err := os.ReadFile(filepath.Join(h.dir, name))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("history changed: %s: %v", name, err)
				}
			}
			info, err := os.Stat(live)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("live mode: %v", err)
			}
		})
	}
}
