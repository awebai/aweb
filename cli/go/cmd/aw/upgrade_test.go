package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.6.0", "0.7.0", -1},
		{"0.7.0", "0.7.0", 0},
		{"1.0.0", "0.9.0", 1},
		{"0.6.0", "0.10.0", -1},
		{"1.2.3", "1.2.3", 0},
		{"2.0.0", "1.99.99", 1},
		{"0.0.1", "0.0.2", -1},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tt.a, tt.b), func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestFetchLatestRelease(t *testing.T) {
	release := map[string]interface{}{
		"tag_name": "v0.7.0",
		"assets": []map[string]interface{}{
			{"name": "aw_0.7.0_darwin_arm64.tar.gz", "browser_download_url": "https://example.com/aw_0.7.0_darwin_arm64.tar.gz"},
			{"name": "aw_0.7.0_linux_amd64.tar.gz", "browser_download_url": "https://example.com/aw_0.7.0_linux_amd64.tar.gz"},
			{"name": "checksums.txt", "browser_download_url": "https://example.com/checksums.txt"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/awebai/aw/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	info, err := fetchLatestRelease(3, server.URL)
	if err != nil {
		t.Fatalf("fetchLatestRelease failed: %v", err)
	}

	if info.TagName != "v0.7.0" {
		t.Errorf("TagName = %q, want %q", info.TagName, "v0.7.0")
	}
	if len(info.Assets) != 3 {
		t.Errorf("got %d assets, want 3", len(info.Assets))
	}
	if info.Assets[0].Name != "aw_0.7.0_darwin_arm64.tar.gz" {
		t.Errorf("first asset name = %q, want %q", info.Assets[0].Name, "aw_0.7.0_darwin_arm64.tar.gz")
	}
}

func TestVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "testfile")
	content := []byte("hello world")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256(content)
	correctChecksum := fmt.Sprintf("%x", hash)

	t.Run("correct checksum passes", func(t *testing.T) {
		if err := verifyChecksum(filePath, correctChecksum); err != nil {
			t.Errorf("verifyChecksum with correct checksum failed: %v", err)
		}
	})

	t.Run("wrong checksum fails", func(t *testing.T) {
		err := verifyChecksum(filePath, "0000000000000000000000000000000000000000000000000000000000000000")
		if err == nil {
			t.Error("verifyChecksum with wrong checksum should fail")
		}
		if !strings.Contains(err.Error(), "checksum mismatch") {
			t.Errorf("error should mention checksum mismatch, got: %v", err)
		}
	})
}

func TestExtractBinary(t *testing.T) {
	binaryContent := []byte("#!/bin/bash\necho hello\n")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: "aw",
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(binaryContent); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()

	dir := t.TempDir()
	archivePath := filepath.Join(dir, "aw_0.7.0_linux_amd64.tar.gz")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	destDir := filepath.Join(dir, "extracted")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := extractBinary(archivePath, "aw", destDir); err != nil {
		t.Fatalf("extractBinary failed: %v", err)
	}

	extracted, err := os.ReadFile(filepath.Join(destDir, "aw"))
	if err != nil {
		t.Fatalf("reading extracted binary: %v", err)
	}
	if !bytes.Equal(extracted, binaryContent) {
		t.Error("extracted binary content does not match original")
	}
}

func TestExtractBinary_PathTraversal(t *testing.T) {
	// Create a tar.gz archive with a path-traversal entry and a legitimate binary.
	// extractBinary should skip the malicious entry and only find the legitimate one.
	legitimateContent := []byte("#!/bin/bash\necho legit\n")
	maliciousContent := []byte("#!/bin/bash\necho evil\n")

	tests := []struct {
		name         string
		malPath      string
		includeLegit bool
		wantErr      bool
	}{
		{"relative traversal", "../../etc/passwd", true, false},
		{"absolute path", "/tmp/exploit", true, false},
		{"deep traversal", "foo/../../../bin/evil", true, false},
		{"traversal only", "../../etc/passwd", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gw)

			// Write malicious entry
			malHdr := &tar.Header{
				Name: tt.malPath,
				Mode: 0755,
				Size: int64(len(maliciousContent)),
			}
			if err := tw.WriteHeader(malHdr); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(maliciousContent); err != nil {
				t.Fatal(err)
			}

			// Optionally write legitimate binary
			if tt.includeLegit {
				legitHdr := &tar.Header{
					Name: "aw",
					Mode: 0755,
					Size: int64(len(legitimateContent)),
				}
				if err := tw.WriteHeader(legitHdr); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(legitimateContent); err != nil {
					t.Fatal(err)
				}
			}

			tw.Close()
			gw.Close()

			dir := t.TempDir()
			archivePath := filepath.Join(dir, "test.tar.gz")
			if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}

			destDir := filepath.Join(dir, "extracted")
			if err := os.MkdirAll(destDir, 0755); err != nil {
				t.Fatal(err)
			}

			err := extractBinary(archivePath, "aw", destDir)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error for traversal-only archive")
				}
				return
			}
			if err != nil {
				t.Fatalf("extractBinary failed: %v", err)
			}

			// Verify only the legitimate binary was extracted
			extracted, err := os.ReadFile(filepath.Join(destDir, "aw"))
			if err != nil {
				t.Fatalf("reading extracted binary: %v", err)
			}
			if !bytes.Equal(extracted, legitimateContent) {
				t.Error("extracted content does not match legitimate binary")
			}

			// Verify malicious paths were NOT extracted
			malBase := filepath.Base(tt.malPath)
			if _, err := os.Stat(filepath.Join(destDir, malBase)); err == nil {
				t.Errorf("malicious file %q should not exist in destDir", malBase)
			}
		})
	}
}

func TestFindChecksum(t *testing.T) {
	dir := t.TempDir()
	checksumsPath := filepath.Join(dir, "checksums.txt")

	content := "abc123def456  aw_0.7.0_linux_amd64.tar.gz\nfff000aaa111  aw_0.7.0_darwin_arm64.tar.gz\n"
	if err := os.WriteFile(checksumsPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("finds matching checksum", func(t *testing.T) {
		got, err := findChecksum(checksumsPath, "aw_0.7.0_linux_amd64.tar.gz")
		if err != nil {
			t.Fatalf("findChecksum failed: %v", err)
		}
		if got != "abc123def456" {
			t.Errorf("got %q, want %q", got, "abc123def456")
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := findChecksum(checksumsPath, "aw_0.7.0_windows_amd64.zip")
		if err == nil {
			t.Error("expected error for missing checksum entry")
		}
	})
}

func TestDownloadFile_RejectsHTTP(t *testing.T) {
	err := downloadFile(filepath.Join(t.TempDir(), "test"), "http://example.com/file")
	if err == nil {
		t.Error("expected error for non-HTTPS URL")
	}
	if !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("error should mention non-HTTPS, got: %v", err)
	}
}

func TestSelfUpdate_DevVersion(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "dev"

	var buf bytes.Buffer
	err := selfUpdate(&buf, "")
	if err != nil {
		t.Fatalf("selfUpdate returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "dev build") {
		t.Errorf("expected dev build warning, got: %s", output)
	}
}

func TestSelfUpdate_AlreadyCurrent(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "0.7.0"

	release := map[string]interface{}{
		"tag_name": "v0.7.0",
		"assets":   []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	var buf bytes.Buffer
	err := selfUpdate(&buf, server.URL)
	if err != nil {
		t.Fatalf("selfUpdate returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "already the latest") {
		t.Errorf("expected 'already the latest', got: %s", output)
	}
}

func TestCheckLatestVersion(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "0.6.0"

	release := map[string]interface{}{
		"tag_name": "v0.7.0",
		"assets":   []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	var buf bytes.Buffer
	checkLatestVersion(&buf, server.URL)

	output := buf.String()
	if !strings.Contains(output, "Upgrade available") {
		t.Errorf("expected upgrade hint, got: %s", output)
	}
	if !strings.Contains(output, "0.6.0") || !strings.Contains(output, "0.7.0") {
		t.Errorf("expected both versions in output, got: %s", output)
	}
}

func TestCheckLatestVersion_AlreadyCurrent(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "0.7.0"

	release := map[string]interface{}{
		"tag_name": "v0.7.0",
		"assets":   []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	var buf bytes.Buffer
	checkLatestVersion(&buf, server.URL)

	output := buf.String()
	if output != "" {
		t.Errorf("expected no output when current, got: %s", output)
	}
}

func TestCheckLatestVersion_DevVersion(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "dev"

	var buf bytes.Buffer
	checkLatestVersion(&buf, "http://localhost:0")

	output := buf.String()
	if output != "" {
		t.Errorf("expected no output for dev version, got: %s", output)
	}
}

func TestPersistentPreRunSkipsOnJSONFlag(t *testing.T) {
	calls := 0
	server := updateCheckTestServer(t, "v2.0.0", &calls)
	defer server.Close()
	var buf bytes.Buffer
	resetUpdateCheckTestState(t, "1.0.0", server.URL, &buf, true)
	jsonFlag = true

	maybeCheckLatestVersion(testCommandPath("aw", "mail", "inbox"))

	if calls != 0 {
		t.Fatalf("release calls=%d, want 0", calls)
	}
	if buf.String() != "" {
		t.Fatalf("output=%q, want empty", buf.String())
	}
}

func TestPersistentPreRunSkipsOnNonTTYStdout(t *testing.T) {
	calls := 0
	server := updateCheckTestServer(t, "v2.0.0", &calls)
	defer server.Close()
	var buf bytes.Buffer
	resetUpdateCheckTestState(t, "1.0.0", server.URL, &buf, false)

	maybeCheckLatestVersion(testCommandPath("aw", "mail", "inbox"))

	if calls != 0 {
		t.Fatalf("release calls=%d, want 0", calls)
	}
	if buf.String() != "" {
		t.Fatalf("output=%q, want empty", buf.String())
	}
}

func TestPersistentPreRunSkipsOnEnvVar(t *testing.T) {
	calls := 0
	server := updateCheckTestServer(t, "v2.0.0", &calls)
	defer server.Close()
	var buf bytes.Buffer
	resetUpdateCheckTestState(t, "1.0.0", server.URL, &buf, true)
	t.Setenv("AW_NO_UPDATE_CHECK", "1")

	maybeCheckLatestVersion(testCommandPath("aw", "mail", "inbox"))

	if calls != 0 {
		t.Fatalf("release calls=%d, want 0", calls)
	}
	if buf.String() != "" {
		t.Fatalf("output=%q, want empty", buf.String())
	}
}

func TestPersistentPreRunSkipsOnSkipListCommand(t *testing.T) {
	for _, path := range [][]string{
		{"aw", "heartbeat"},
		{"aw", "run"},
		{"aw", "events"},
		{"aw", "lock", "renew"},
	} {
		t.Run(strings.Join(path[1:], "_"), func(t *testing.T) {
			calls := 0
			server := updateCheckTestServer(t, "v2.0.0", &calls)
			defer server.Close()
			var buf bytes.Buffer
			resetUpdateCheckTestState(t, "1.0.0", server.URL, &buf, true)

			maybeCheckLatestVersion(testCommandPath(path...))

			if calls != 0 {
				t.Fatalf("release calls=%d, want 0", calls)
			}
			if buf.String() != "" {
				t.Fatalf("output=%q, want empty", buf.String())
			}
		})
	}
}

func TestPersistentPreRunFiresOnAlwaysListCommand(t *testing.T) {
	calls := 0
	server := updateCheckTestServer(t, "v2.0.0", &calls)
	defer server.Close()
	var buf bytes.Buffer
	resetUpdateCheckTestState(t, "1.0.0", server.URL, &buf, true)

	maybeCheckLatestVersion(testCommandPath("aw", "mail", "inbox"))

	if calls != 1 {
		t.Fatalf("release calls=%d, want 1", calls)
	}
	output := buf.String()
	if !strings.Contains(output, "Upgrade available") || !strings.Contains(output, "v1.0.0") || !strings.Contains(output, "v2.0.0") {
		t.Fatalf("unexpected output=%q", output)
	}
}

func TestUpdateCacheRespects1HourTTL(t *testing.T) {
	calls := 0
	server := updateCheckTestServer(t, "v3.0.0", &calls)
	defer server.Close()
	var buf bytes.Buffer
	now := time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC)
	cachePath := resetUpdateCheckTestState(t, "1.0.0", server.URL, &buf, true)
	updateCheckNow = func() time.Time { return now }
	writeUpdateCheckCache(updateCheckCache{CheckedAt: now, LatestVersion: "2.0.0"})

	checkLatestVersionWithCache(&buf, "1.0.0", server.URL)
	if calls != 0 {
		t.Fatalf("release calls on fresh cache=%d, want 0", calls)
	}
	if !strings.Contains(buf.String(), "v2.0.0") {
		t.Fatalf("fresh-cache output=%q, want cached latest version", buf.String())
	}

	buf.Reset()
	updateCheckNow = func() time.Time { return now.Add(updateCheckCacheTTL + time.Second) }
	checkLatestVersionWithCache(&buf, "1.0.0", server.URL)
	if calls != 1 {
		t.Fatalf("release calls after stale cache=%d, want 1", calls)
	}
	if !strings.Contains(buf.String(), "v3.0.0") {
		t.Fatalf("stale-cache output=%q, want fetched latest version", buf.String())
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file missing after write: %v", err)
	}
}

func TestUpdateCacheBestEffortWriteFailure(t *testing.T) {
	calls := 0
	server := updateCheckTestServer(t, "v2.0.0", &calls)
	defer server.Close()
	var buf bytes.Buffer
	resetUpdateCheckTestState(t, "1.0.0", server.URL, &buf, true)
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block mkdir"), 0644); err != nil {
		t.Fatal(err)
	}
	updateCheckCachePath = func() string {
		return filepath.Join(blocker, "aw", "update-check.json")
	}

	checkLatestVersionWithCache(&buf, "1.0.0", server.URL)

	if calls != 1 {
		t.Fatalf("release calls=%d, want 1", calls)
	}
	if !strings.Contains(buf.String(), "Upgrade available") {
		t.Fatalf("output=%q, want upgrade hint", buf.String())
	}
}

func resetUpdateCheckTestState(t *testing.T, testVersion, apiBase string, output *bytes.Buffer, stdoutTTY bool) string {
	t.Helper()
	oldVersion := version
	oldJSONFlag := jsonFlag
	oldAPIBase := updateCheckAPIBase
	oldOutput := updateCheckOutput
	oldNow := updateCheckNow
	oldStdoutIsTTY := updateCheckStdoutIsTTY
	oldCachePath := updateCheckCachePath
	version = testVersion
	jsonFlag = false
	updateCheckAPIBase = apiBase
	updateCheckOutput = output
	updateCheckNow = func() time.Time { return time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC) }
	updateCheckStdoutIsTTY = func() bool { return stdoutTTY }
	cachePath := filepath.Join(t.TempDir(), "aw", "update-check.json")
	updateCheckCachePath = func() string { return cachePath }
	t.Setenv("AW_NO_UPDATE_CHECK", "")
	t.Cleanup(func() {
		version = oldVersion
		jsonFlag = oldJSONFlag
		updateCheckAPIBase = oldAPIBase
		updateCheckOutput = oldOutput
		updateCheckNow = oldNow
		updateCheckStdoutIsTTY = oldStdoutIsTTY
		updateCheckCachePath = oldCachePath
	})
	return cachePath
}

func updateCheckTestServer(t *testing.T, tagName string, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/awebai/aw/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		*calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": tagName,
			"assets":   []map[string]any{},
		})
	}))
}

func testCommandPath(parts ...string) *cobra.Command {
	if len(parts) == 0 {
		return &cobra.Command{Use: "aw"}
	}
	root := &cobra.Command{Use: parts[0]}
	current := root
	for _, part := range parts[1:] {
		child := &cobra.Command{Use: part}
		current.AddCommand(child)
		current = child
	}
	return current
}
