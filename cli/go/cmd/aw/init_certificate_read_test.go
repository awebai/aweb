package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestInitDoesNotTreatUnreadableCertificatesAsFreshHome(t *testing.T) {
	for _, sample := range []struct {
		Name    string
		Prepare func(*testing.T, string)
	}{
		{Name: "malformed certificate", Prepare: func(t *testing.T, directory string) {
			t.Helper()
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "broken.pem"), []byte("not a certificate"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{Name: "certificate directory is a file", Prepare: func(t *testing.T, directory string) {
			t.Helper()
			if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(directory, []byte("blocked directory"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(sample.Name, func(t *testing.T) {
			workingDir := t.TempDir()
			t.Chdir(workingDir)
			directory := awconfig.TeamCertificatesDir(workingDir)
			sample.Prepare(t, directory)
			_, readErr := awconfig.ListTeamCertificates(workingDir)
			if readErr == nil {
				t.Fatal("filesystem setup did not reach the certificate read failure")
			}
			dispatch, err := runInitFromExistingCertificate(authTestCmd(&bytes.Buffer{}))
			if err == nil || !strings.Contains(err.Error(), readErr.Error()) || dispatch != initDispatchComplete {
				t.Fatalf("unreadable stored certificate allowed fresh creation: dispatch=%v err=%v; read error=%v", dispatch, err, readErr)
			}
		})
	}
}

func TestInitWithoutStoredCertificatesMayContinueOnboarding(t *testing.T) {
	t.Chdir(t.TempDir())
	result, err := runInitFromExistingCertificate(authTestCmd(&bytes.Buffer{}))
	if err != nil || result != initDispatchDeferred {
		t.Fatalf("fresh home cannot continue onboarding: %v %v", result, err)
	}
}
