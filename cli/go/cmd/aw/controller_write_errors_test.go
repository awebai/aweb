package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// seedAWIDNamespace stores a verified namespace in the fixture's database:
// a registry without AWID_PUBLIC_ORIGINS refuses aw's own registration of it.
func seedAWIDNamespace(t *testing.T, storage realAWIDStorage, domain, controllerDID string) {
	t.Helper()
	project, err := filepath.Abs("../../../../awid")
	if err != nil {
		t.Fatal(err)
	}
	cache := exec.Command("uv", "cache", "dir")
	cache.Env = awTestBinary.env
	cache.Dir = awTestBinary.sourceDir
	cacheDir, err := cache.Output()
	if err != nil {
		t.Fatalf("resolve parent uv cache: %v", err)
	}
	insert := `import asyncio, os, sys, asyncpg
async def main():
    connection = await asyncpg.connect(os.environ["AWID_DATABASE_URL"])
    try:
        await connection.execute(
            'INSERT INTO "' + os.environ["AWID_DB_SCHEMA"] + '".dns_namespaces '
            "(domain, controller_did, verification_status) VALUES ($1, $2, 'verified')",
            sys.argv[1], sys.argv[2])
    finally:
        await connection.close()
asyncio.run(main())`
	cmd := exec.Command("uv", "run", "--offline", "--frozen", "--project", project, "python", "-c", insert, domain, controllerDID)
	cmd.Env = append(os.Environ(),
		"UV_CACHE_DIR="+strings.TrimSpace(string(cacheDir)),
		"AWID_DATABASE_URL="+storage.DatabaseURL,
		"AWID_DB_SCHEMA="+storage.Schema,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed AWID namespace: %v\n%s", err, out)
	}
}

// A registry without AWID_PUBLIC_ORIGINS refuses every covering controller
// write with 503; aw shows the registry's message, which names the setting,
// both as text and in --json, for a team create and for an address write.
func TestRegistryWithoutPublicOriginsNamesTheSettingToTheUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL, storage := startAWIDFixture(t, "AWID_FIXTURE_PUBLIC_ORIGINS=none")
	domain := "origins.test"
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeControllerKeyForTest(t, tmp, domain, controllerKey)
	seedAWIDNamespace(t, storage, domain, didOf(controllerKey))
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	setup := awid.NewAWIDRegistryClient(&http.Client{Timeout: 20 * time.Second}, nil)
	if err := setup.TrustRegistryOrigin(registryURL); err != nil {
		t.Fatal(err)
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
