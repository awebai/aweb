package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestHostedInviteRecoveryOmitsUnusedResponseCredential(t *testing.T) {
	response := awid.SpawnAcceptInviteResponse{APIKey: "unused-test-credential", TeamID: "backend:example.com", TeamCert: "retained-certificate", ServerURL: "https://service.example"}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	state := &hostedInviteCreation{ResponseJSON: string(raw), Tree: &hostedIDTreeRecovery{RequestID: "retained-request"}}
	path := filepath.Join(t.TempDir(), "hosted-invite-creation.json")
	if err := state.save(path); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), response.APIKey) {
		t.Fatal("unused response credential was persisted")
	}
	var saved hostedInviteCreation
	if err := json.Unmarshal(stored, &saved); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(saved.ResponseJSON), &fields); err != nil {
		t.Fatal(err)
	}
	if _, present := fields["api_key"]; present {
		t.Fatal("recovery still contains the unused API-key field")
	}
	var replay awid.SpawnAcceptInviteResponse
	if err := json.Unmarshal([]byte(saved.ResponseJSON), &replay); err != nil {
		t.Fatal(err)
	}
	if replay.TeamCert != response.TeamCert || replay.TeamID != response.TeamID || replay.ServerURL != response.ServerURL {
		t.Fatal("credential removal changed the installation response")
	}
	if response.APIKey != "unused-test-credential" {
		t.Fatal("saving changed the caller's response")
	}
}

func TestHostedInviteRecoveryDoesNotRewriteUnknownResponseFields(t *testing.T) {
	state := &hostedInviteCreation{ResponseJSON: `{"team_cert":"certificate","future_public_field":{"v":1},"api_key":"unused"}`}
	path := filepath.Join(t.TempDir(), "recovery.json")
	if err := state.save(path); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved hostedInviteCreation
	if err := json.Unmarshal(stored, &saved); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(saved.ResponseJSON), &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["future_public_field"]) != `{"v":1}` {
		t.Fatal("saving dropped an unknown response field")
	}
}
