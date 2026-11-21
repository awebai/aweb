package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestGuidedOnboardingUnreadableMembershipNeverStartsCreation(t *testing.T) {
	directory := t.TempDir()
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(directory), key); err != nil {
		t.Fatal(err)
	}
	certs := awconfig.TeamCertificatesDir(directory)
	if err := os.MkdirAll(certs, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(certs, "invalid.pem")
	original := []byte("malformed certificate\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; http.Error(w, "creation must not start", 503) }))
	defer server.Close()
	_, err = executeGuidedOnboardingWizard(guidedOnboardingRequest{WorkingDir: directory, BaseURL: server.URL, Username: "existing", Alias: "existing", NonInteractive: true})
	if err == nil || !strings.Contains(err.Error(), "reconnect membership") || calls != 0 {
		t.Fatalf("unreadable membership selected another creation: calls=%d error=%v", calls, err)
	}
	kept, readErr := os.ReadFile(path)
	if readErr != nil || string(kept) != string(original) {
		t.Fatalf("unreadable membership changed: %v", readErr)
	}
}
