package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// A child process installs its private TLS root without changing other tests'
// trust store. The command still uses the production transport and signer.
func TestHumanRefreshBindingCarriesHolderRecoveryAdvice(t *testing.T) {
	if os.Getenv("AW_TEST_HOLDER_ADVICE_CHILD") != "1" {
		child := exec.Command(os.Args[0], "-test.run=^TestHumanRefreshBindingCarriesHolderRecoveryAdvice$", "-test.v")
		child.Env = append(os.Environ(), "AW_TEST_HOLDER_ADVICE_CHILD=1", "GODEBUG=x509usefallbackroots=1")
		output, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("command entry-point regression: %v\n%s", err, output)
		}
		return
	}
	const code = "binding_refresh_identity_key_changed"
	const advice = "The person's identity key changed. Binding refresh cannot replace it; ask the operator for enrolment or recovery. In this release the operator must revoke the old ID, issue a new ID and enrol again."
	h, _, _ := commandUnlockFixture(t, humanPassphrase)
	originalHuman, originalIssuer := activeHuman, humanRefreshIssuer
	activeHuman = h
	t.Cleanup(func() { activeHuman, humanRefreshIssuer = originalHuman, originalIssuer })
	// This command only commits the retained binding before the holder refuses;
	// no enrollment verification is claimed by the transport regression.
	binding := map[string]any{"binding": map[string]any{"person": h.record.StableID, "identity_key": h.record.DIDKey, "organisation": h.record.Domain, "origin": "https://approval.example.test"}, "signature": "retained-enrollment"}
	if err := saveHumanEnrollment(filepath.Join(h.dir, "approval-binding.json"), binding); err != nil {
		t.Fatal(err)
	}
	// A live binding must remain distinct from the original enrollment evidence.
	if err := saveHumanEnrollment(filepath.Join(h.dir, "approval-live-binding.json"), binding); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"approval-evidence.json", "enrollment-session.json"} {
		if err := os.WriteFile(filepath.Join(h.dir, name), []byte("retained history\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	snapshots := make(map[string][]byte)
	for _, name := range []string{"approval-binding.json", "approval-live-binding.json", "approval-evidence.json", "enrollment-session.json"} {
		raw, err := os.ReadFile(filepath.Join(h.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		snapshots[name] = raw
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/enrollments/"+h.record.StableID+"/refresh-binding" {
			t.Errorf("unexpected holder target %s %s", r.Method, r.URL.Path)
		}
		auth := strings.Fields(r.Header.Get("Authorization"))
		payload, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		if err != nil || len(auth) != 3 {
			t.Errorf("missing covering identity signature")
			w.WriteHeader(401)
			return
		}
		status, err := awid.VerifySignedPayload(string(payload), auth[2], h.record.DIDKey, "")
		if err != nil || status != awid.Verified {
			t.Errorf("invalid signature: %s, %v", status, err)
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		if err := json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": advice}}); err != nil {
			t.Errorf("write refusal: %v", err)
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	x509.SetFallbackRoots(roots)
	humanRefreshIssuer = server.URL
	cmd := &cobra.Command{Use: "refresh-binding", RunE: runIDHumanRefreshBinding}
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	if calls.Load() != 1 {
		t.Fatalf("holder calls: %d", calls.Load())
	}
	if err == nil || !strings.Contains(err.Error(), advice) || errorCodeOf(err) != code || exitCode(err) != 1 {
		t.Fatalf("holder recovery advice/code lost: %v (code %q)", err, errorCodeOf(err))
	}
	for name, want := range snapshots {
		got, err := os.ReadFile(filepath.Join(h.dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("changed %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(h.dir, "approval-binding-refresh.json")); !os.IsNotExist(err) {
		t.Fatalf("refused holder created a pending packet: %v", err)
	}
}
