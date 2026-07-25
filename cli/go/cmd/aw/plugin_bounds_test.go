package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

// interruptedReader yields n bytes then fails, simulating a truncated/aborted
// stream.
type interruptedReader struct{ remaining int }

func (r *interruptedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("connection reset")
	}
	p[0] = 'x'
	r.remaining--
	return 1, nil
}

func TestReadAllBoundedPropagatesInterruptedRead(t *testing.T) {
	if _, err := readAllBounded(&interruptedReader{remaining: 3}, 100); err == nil {
		t.Fatal("expected an interrupted read to propagate an error, not silently truncate")
	}
}

func TestCopyBoundedPropagatesInterruptedRead(t *testing.T) {
	var dst strings.Builder
	if _, err := copyBounded(&dst, &interruptedReader{remaining: 3}, 100, sha256.New()); err == nil {
		t.Fatal("expected an interrupted copy to propagate an error")
	}
}

func TestReadAllBounded(t *testing.T) {
	cases := []struct {
		n, max  int64
		wantErr bool
	}{
		{5, 10, false},  // under
		{10, 10, false}, // exactly at limit accepted
		{11, 10, true},  // one byte over rejected
	}
	for _, tc := range cases {
		data, err := readAllBounded(strings.NewReader(strings.Repeat("x", int(tc.n))), tc.max)
		if tc.wantErr {
			if err == nil {
				t.Errorf("n=%d max=%d: expected oversize error", tc.n, tc.max)
			}
			continue
		}
		if err != nil || int64(len(data)) != tc.n {
			t.Errorf("n=%d max=%d: len=%d err=%v", tc.n, tc.max, len(data), err)
		}
	}
}

func TestCopyBounded(t *testing.T) {
	var dst strings.Builder
	h := sha256.New()
	if n, err := copyBounded(&dst, strings.NewReader(strings.Repeat("a", 10)), 10, h); err != nil || n != 10 || dst.Len() != 10 {
		t.Fatalf("at-limit: n=%d dstLen=%d err=%v", n, dst.Len(), err)
	}
	dst.Reset()
	h.Reset()
	if _, err := copyBounded(&dst, strings.NewReader(strings.Repeat("a", 11)), 10, h); err == nil {
		t.Fatal("one byte over: expected error")
	}
}

func TestInstallPluginSourceLocalBounds(t *testing.T) {
	dir := t.TempDir()
	defer func(old int64) { maxPluginBytes = old }(maxPluginBytes)
	maxPluginBytes = 100

	// Exactly at limit installs.
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte(strings.Repeat("x", 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "dest")
	if _, err := installPluginSource(src, dest); err != nil {
		t.Fatalf("at-limit install: %v", err)
	}
	if info, err := os.Stat(dest); err != nil || info.Size() != 100 {
		t.Fatalf("dest missing/wrong size: %v", err)
	}

	// Oversized source: error, no artifact at destination, temp cleaned.
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", 101)), 0o644); err != nil {
		t.Fatal(err)
	}
	dest2 := filepath.Join(dir, "dest2")
	if _, err := installPluginSource(big, dest2); err == nil {
		t.Fatal("oversized source: expected error")
	}
	if _, err := os.Stat(dest2); !os.IsNotExist(err) {
		t.Fatal("oversized artifact appeared at destination")
	}
	if _, err := os.Stat(dest2 + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file not cleaned up after oversize failure")
	}
}

func TestInstallPluginSourceOversizedUpdatePreservesOld(t *testing.T) {
	dir := t.TempDir()
	defer func(old int64) { maxPluginBytes = old }(maxPluginBytes)
	maxPluginBytes = 100

	dest := filepath.Join(dir, "dest")
	if err := os.WriteFile(dest, []byte("OLD-INSTALL"), 0o755); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", 200)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installPluginSource(big, dest); err == nil {
		t.Fatal("expected oversize error on update")
	}
	if data, _ := os.ReadFile(dest); string(data) != "OLD-INSTALL" {
		t.Fatalf("previous install was overwritten: %q", data)
	}
	if _, err := os.Stat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file not cleaned up")
	}
}

func TestInstallPluginSourceHTTPBounds(t *testing.T) {
	dir := t.TempDir()
	defer func(old int64) { maxPluginBytes = old }(maxPluginBytes)
	maxPluginBytes = 100

	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("y", 100)))
	}))
	defer okSrv.Close()
	dest := filepath.Join(dir, "http-dest")
	if _, err := installPluginSource(okSrv.URL, dest); err != nil {
		t.Fatalf("at-limit HTTP install: %v", err)
	}
	if info, err := os.Stat(dest); err != nil || info.Size() != 100 {
		t.Fatalf("HTTP dest missing/wrong: %v", err)
	}

	bigSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("y", 500)))
	}))
	defer bigSrv.Close()
	dest2 := filepath.Join(dir, "http-dest2")
	if _, err := installPluginSource(bigSrv.URL, dest2); err == nil {
		t.Fatal("oversized HTTP source: expected error")
	}
	if _, err := os.Stat(dest2); !os.IsNotExist(err) {
		t.Fatal("oversized HTTP artifact appeared at destination")
	}
}

func TestFetchManifestBounds(t *testing.T) {
	defer func(old int64) { maxManifestBytes = old }(maxManifestBytes)
	maxManifestBytes = 50

	body := strings.Repeat("m", 50)
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer okSrv.Close()
	data, digest, err := fetchManifest(okSrv.URL)
	if err != nil || len(data) != 50 {
		t.Fatalf("at-limit manifest: len=%d err=%v", len(data), err)
	}
	sum := sha256.Sum256([]byte(body))
	if digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("digest does not cover the complete accepted bytes")
	}

	bigSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("m", 51)))
	}))
	defer bigSrv.Close()
	if _, _, err := fetchManifest(bigSrv.URL); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}

func TestExecuteUnsignedManifestResponseBound(t *testing.T) {
	defer func(old int64) { maxResponseBytes = old }(maxResponseBytes)
	maxResponseBytes = 50

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("r", 100)))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if _, err := executeUnsignedManifestRequest("GET", u, nil, http.Header{}); err == nil {
		t.Fatal("oversized response body accepted")
	}
}

func TestExecuteSignedManifestResponseBound(t *testing.T) {
	defer func(old int64) { maxResponseBytes = old }(maxResponseBytes)
	maxResponseBytes = 50

	tmp := t.TempDir()
	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("r", 100)))
	}))
	defer srv.Close()
	writeLocalTeamSignedRequestWorkspaceForTest(t, tmp, srv.URL, "default:acme.com", "alice", did, priv)
	identity := &localSigningIdentity{DIDKey: did, SigningKey: priv, WorkingDir: tmp, TeamID: "default:acme.com"}

	u, err := url.Parse(srv.URL + "/v1/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeSignedIDRequest(http.MethodPost, u, identity, []byte("{}"), make(http.Header), map[string]any{}, true); err == nil {
		t.Fatal("oversized signed response body accepted")
	}
}

func TestReadManifestBodyFileBound(t *testing.T) {
	dir := t.TempDir()
	defer func(old int64) { maxBodyFileBytes = old }(maxBodyFileBytes)
	maxBodyFileBytes = 50

	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte(strings.Repeat("b", 50)), 0o644); err != nil {
		t.Fatal(err)
	}
	if data, err := readManifestBodyFile(small); err != nil || len(data) != 50 {
		t.Fatalf("at-limit body-file: len=%d err=%v", len(data), err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("b", 51)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifestBodyFile(big); err == nil {
		t.Fatal("oversized body-file accepted")
	}
}
