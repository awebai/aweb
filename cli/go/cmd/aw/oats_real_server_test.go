package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

func TestOATSRealSingletonWorkspaceStatus(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	out := world.requireCommand(t, member.Home, "workspace", "status")
	var result map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if string(result["team"]) != "[]" {
		t.Fatalf("singleton roster must carry team: []: %s", out)
	}
}

func TestOATSRealExplicitHomeJoinFrom(t *testing.T) {
	world := newRealCommandWorld(t)
	source := world.addLocalMember(t, "root")
	target := filepath.Join(t.TempDir(), "named-identity")
	t.Setenv("HOME", filepath.Dir(target))
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	sourceBefore := fileDigestsForTest(t, source.Home)
	out := world.requireCommand(t, target, "init", "--join-from", source.Home, "--join-team", world.TeamID, "--name", "worker", "--do-not-touch-agents-md")
	if strings.Contains(out, "aw_inv_") {
		t.Fatalf("join exposed invite token: %s", out)
	}
	status := world.requireCommand(t, target, "id", "status", "--team", world.TeamID)
	var result identityStatusOutput
	if err := json.Unmarshal([]byte(status), &result); err != nil {
		t.Fatalf("status: %v\n%s", err, status)
	}
	if !result.MintComplete || result.Alias != "worker" {
		t.Fatalf("explicit target incomplete: %s", status)
	}
	if _, err := os.Stat(filepath.Join(target, "signing.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(target), ".aw", "signing.key")); !os.IsNotExist(err) {
		t.Fatalf("join wrote checkout identity: %v", err)
	}
	after := fileDigestsForTest(t, source.Home)
	if len(after) != len(sourceBefore) {
		t.Fatal("source state changed")
	}
	for path, digest := range sourceBefore {
		if after[path] != digest {
			t.Fatalf("source changed: %s", path)
		}
	}
}

func TestOATSRealServiceRegisterPreservesCode(t *testing.T) {
	world := newRealCommandWorld(t)
	target, err := resolveTeamRegistrationEndpoint(world.Stack.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = executeTeamRegisterWithTarget(world.Context, world.TeamKey, world.TeamID, target, false, time.Now().Add(-24*time.Hour).UTC().Format(time.RFC3339))
	if err == nil {
		t.Fatal("server must refuse an expired registration timestamp")
	}
	envelope := errorEnvelope(err, err.Error())
	if envelope.Error.Code != "invalid_controller_timestamp" || envelope.Error.HTTPStatus != 400 {
		t.Fatalf("lost service code: %#v; %v", envelope, err)
	}
	if !strings.Contains(err.Error(), "service register: http 400:") {
		t.Fatalf("changed registration refusal sentence: %v", err)
	}
}

func TestOATSRealControllerRetirement(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	t.Setenv("HOME", filepath.Dir(member.Home))
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	out := world.requireCommand(t, member.Home, "id", "status", "--team", world.TeamID)
	var status identityStatusOutput
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatal(err)
	}
	out = world.requireCommand(t, member.Home, "workspace", "delete", status.WorkspaceID)
	var retired workspaceDeleteOutput
	if err := json.Unmarshal([]byte(out), &retired); err != nil {
		t.Fatalf("delete: %v\n%s", err, out)
	}
	if !retired.AliasReleased {
		t.Fatalf("controller-holder retirement leaked active membership: %s", out)
	}
	certificate, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.Certificate.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Status != "revoked" {
		t.Fatalf("reported complete with active certificate: %#v", certificate)
	}
}
