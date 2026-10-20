package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// realAWIDStorage names the fixture's database, for seeding state the CLI cannot
// publish itself.
type realAWIDStorage struct {
	DatabaseURL string `json:"database_url"`
	Schema      string `json:"schema"`
}

// realAWIDFixture runs the repository's real service with disposable storage.
// It is test-only; neither a response mock nor a production registry fallback.
func realAWIDFixture(t *testing.T) string {
	t.Helper()
	registryURL, _ := realAWIDFixtureWithStorage(t)
	return registryURL
}

// realAWIDFixtureWithStorage is realAWIDFixture plus the fixture's storage.
func realAWIDFixtureWithStorage(t *testing.T) (string, realAWIDStorage) {
	t.Helper()
	return startRealAWIDFixture(t, false)
}

// realAWIDFixtureRateLimited runs the fixture with AWID's production rate-limit
// buckets, on an in-memory limiter private to it.
func realAWIDFixtureRateLimited(t *testing.T) (string, realAWIDStorage) {
	t.Helper()
	return startRealAWIDFixture(t, true)
}

func startRealAWIDFixture(t *testing.T, rateLimited bool) (string, realAWIDStorage) {
	t.Helper()
	script, err := filepath.Abs("../../../../scripts/test-egress/awid_fixture.py")
	if err != nil {
		t.Fatal(err)
	}
	// Tests isolate HOME, but uv must keep the parent's populated offline cache.
	cache := exec.Command("uv", "cache", "dir")
	cache.Env = awTestBinary.env
	cache.Dir = awTestBinary.sourceDir
	cacheDir, err := cache.Output()
	if err != nil {
		t.Fatalf("resolve parent uv cache: %v", err)
	}
	cmd := exec.Command("python3", script)
	cmd.Env = append(os.Environ(), "UV_CACHE_DIR="+strings.TrimSpace(string(cacheDir)))
	if rateLimited {
		cmd.Env = append(cmd.Env, "AWID_FIXTURE_RATE_LIMITS=production")
	}
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("real AWID fixture: %v", err)
		}
	})
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() {
		t.Fatal("real AWID fixture failed before publishing its loopback URL")
	}
	registryURL := scanner.Text()
	if !scanner.Scan() {
		t.Fatal("real AWID fixture failed before publishing its storage")
	}
	var storage realAWIDStorage
	if err := json.Unmarshal(scanner.Bytes(), &storage); err != nil {
		t.Fatalf("real AWID fixture storage: %v", err)
	}
	return registryURL, storage
}

// seedAWIDAttestationRecords stores certificates and signed attestation
// records in the fixture's database through
// scripts/test-egress/seed_awid_attestation_records.py. aw cannot publish these
// records itself (their routes take the covering v2 controller envelope); AWID
// verifies them on rotation like published ones.
func seedAWIDAttestationRecords(t *testing.T, storage realAWIDStorage, domain, name string, certificates, records []map[string]any) {
	t.Helper()
	script, err := filepath.Abs("../../../../scripts/test-egress/seed_awid_attestation_records.py")
	if err != nil {
		t.Fatal(err)
	}
	project, err := filepath.Abs("../../../../awid")
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]any{"domain": domain, "name": name, "certificates": certificates, "records": records})
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
	cmd := exec.Command("uv", "run", "--offline", "--frozen", "--project", project, "python", script)
	cmd.Env = append(os.Environ(),
		"UV_CACHE_DIR="+strings.TrimSpace(string(cacheDir)),
		"AWID_DATABASE_URL="+storage.DatabaseURL,
		"AWID_DB_SCHEMA="+storage.Schema,
	)
	cmd.Stdin = bytes.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed AWID attestation records: %v\n%s", err, out)
	}
}
