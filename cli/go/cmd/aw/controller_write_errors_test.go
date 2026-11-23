package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A registry without AWID_PUBLIC_ORIGINS refuses every covering controller
// write with 503; aw shows the registry's message, which names the setting,
// both as text and in --json, for a team create and for an address write.
func TestRegistryWithoutPublicOriginsNamesTheSettingToTheUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	configuredURL, storage := realAWIDFixtureWithStorage(t)
	stored, err := json.Marshal(storage)
	if err != nil {
		t.Fatal(err)
	}
	registryURL, _ := startAWIDFixture(t, "AWID_FIXTURE_PUBLIC_ORIGINS=none", "AWID_FIXTURE_STORAGE="+string(stored))
	domain := "origins.test"
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeControllerKeyForTest(t, tmp, domain, controllerKey)
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	setup := awid.NewAWIDRegistryClient(&http.Client{Timeout: 20 * time.Second}, nil)
	for _, origin := range []string{configuredURL, registryURL} {
		if err := setup.TrustRegistryOrigin(origin); err != nil {
			t.Fatal(err)
		}
	}
	// The namespace was registered while AWID_PUBLIC_ORIGINS was set.
	if _, err := setup.RegisterNamespaceAt(ctx, configuredURL, domain, didOf(controllerKey), controllerKey); err != nil {
		t.Fatalf("register namespace: %v", err)
	}
	memberDIDAW := awid.ComputeStableID(memberPub)
	if _, err := setup.RegisterIdentity(ctx, registryURL, didOf(memberKey), memberDIDAW, memberKey); err != nil {
		t.Fatalf("register identity: %v", err)
	}
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	for _, write := range []struct {
		name string
		args []string
	}{
		{"team create", []string{"id", "team", "create", "--name", "backend", "--namespace", domain, "--registry", registryURL}},
		{"address write", []string{"id", "namespace", "assign-address", "--domain", domain, "--name", "alice", "--did-aw", memberDIDAW}},
	} {
		for _, asJSON := range []bool{false, true} {
			args := write.args
			if asJSON {
				args = append(append([]string{}, args...), "--json")
			}
			run := exec.CommandContext(ctx, bin, args...)
			run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+registryURL)
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("%s (json=%v) succeeded against a registry without AWID_PUBLIC_ORIGINS:\n%s", write.name, asJSON, out)
			}
			t.Logf("%s json=%v:\n%s", write.name, asJSON, out)
			if !strings.Contains(string(out), "AWID_PUBLIC_ORIGINS") {
				t.Fatalf("%s (json=%v) does not show the registry's message:\n%s", write.name, asJSON, out)
			}
		}
	}
}
