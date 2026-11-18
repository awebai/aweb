package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

type versionCheckTransport func(*http.Request) (*http.Response, error)

func (f versionCheckTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestVersionCommandUpdateCheck(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disable  string
		tty      bool
		json     bool
		wantCall bool
	}{
		{name: "disabled", disable: "1", tty: true},
		{name: "nonempty_opt_out", disable: " 0 ", tty: true},
		{name: "non_tty"},
		{name: "json", tty: true, json: true},
		{name: "interactive", tty: true, wantCall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var unused bytes.Buffer
			resetUpdateCheckTestState(t, "1.0.0", "", &unused, tc.tty)
			t.Setenv("AW_NO_UPDATE_CHECK", tc.disable)
			jsonFlag = tc.json
			output, err := os.CreateTemp(t.TempDir(), "version-output")
			if err != nil {
				t.Fatal(err)
			}
			oldStdout, oldStderr, oldTransport := os.Stdout, os.Stderr, http.DefaultTransport
			os.Stdout, os.Stderr = output, output
			t.Cleanup(func() {
				os.Stdout, os.Stderr, http.DefaultTransport = oldStdout, oldStderr, oldTransport
				output.Close()
			})
			calls := 0
			http.DefaultTransport = versionCheckTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://api.github.com/repos/awebai/aw/releases/latest" {
					t.Errorf("unexpected update URL: %s", r.URL)
				}
				if !tc.wantCall {
					// Offline stand-in for a slow network. Skipped checks must never wait here.
					time.Sleep(time.Second)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v2.0.0"}`)), Header: make(http.Header)}, nil
			})
			start := time.Now()
			versionCmd.Run(versionCmd, nil)
			elapsed := time.Since(start)
			if !tc.wantCall && elapsed >= 500*time.Millisecond {
				t.Errorf("version took %s with update checks disabled; want under 500ms", elapsed)
			}
			wantCalls := 0
			if tc.wantCall {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Errorf("release requests=%d, want %d", calls, wantCalls)
			}
			data, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(data), "aw 1.0.0\n") {
				t.Errorf("missing version output: %q", data)
			}
			if gotHint := strings.Contains(string(data), "Upgrade available"); gotHint != tc.wantCall {
				t.Errorf("upgrade hint=%t, want %t: %q", gotHint, tc.wantCall, data)
			}
		})
	}
}

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
		{"1.36.48-rc.1", "1.36.47", 1},
		{"1.36.48-rc.1", "1.36.48", -1},
		{"1.36.48", "1.36.48-rc.1", 1},
		{"1.36.48-rc.2", "1.36.48-rc.10", -1},
		{"1.36.48-rc.10", "1.36.48-rc.2", 1},
		{"1.36.48-rc.1+build", "1.36.48-rc.1", 0},
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
		if err := verifyChecksum(archiveChecksum{Path: filePath, SHA256: correctChecksum}); err != nil {
			t.Errorf("verifyChecksum with correct checksum failed: %v", err)
		}
	})

	t.Run("wrong checksum fails", func(t *testing.T) {
		err := verifyChecksum(archiveChecksum{Path: filePath, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"})
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

	if err := extractBinary(binaryExtraction{ArchivePath: archivePath, BinaryName: "aw", Destination: destDir}); err != nil {
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

			err := extractBinary(binaryExtraction{ArchivePath: archivePath, BinaryName: "aw", Destination: destDir})
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

	content := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  aw_0.7.0_linux_amd64.tar.gz\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  aw_0.7.0_darwin_arm64.tar.gz\n"
	if err := os.WriteFile(checksumsPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("finds matching checksum", func(t *testing.T) {
		got, err := findChecksum(checksumLookup{Path: checksumsPath, ArtifactName: "aw_0.7.0_linux_amd64.tar.gz"})
		if err != nil {
			t.Fatalf("findChecksum failed: %v", err)
		}
		if got != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Errorf("got %q, want %q", got, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := findChecksum(checksumLookup{Path: checksumsPath, ArtifactName: "aw_0.7.0_windows_amd64.zip"})
		if err == nil {
			t.Error("expected error for missing checksum entry")
		}
	})
}

func TestDownloadFile_RejectsHTTP(t *testing.T) {
	err := downloadFile(releaseDownload{Destination: filepath.Join(t.TempDir(), "test"), URL: "http://example.com/file"})
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
		{"aw", "team", "invite", "inspect"},
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

func TestSelfUpdateMissingChecksumRefusesBeforeDownload(t *testing.T) {
	old := version
	version = "1.0.0"
	t.Cleanup(func() { version = old })
	archive := fmt.Sprintf("aw_2.0.0_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		archive = strings.TrimSuffix(archive, "tar.gz") + "zip"
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(releaseInfo{TagName: "v2.0.0", Assets: []releaseAsset{{Name: archive, BrowserDownloadURL: "https://127.0.0.1:1/" + archive}}})
	}))
	defer server.Close()
	var out bytes.Buffer
	err := selfUpdate(&out, server.URL)
	if err == nil || !strings.Contains(err.Error(), archive) || !strings.Contains(err.Error(), "Retry aw upgrade when the release includes checksums.txt.") {
		t.Fatalf("missing actionable digest refusal: %v", err)
	}
}

func TestReplaceBinaryDoesNotTouchPredictableNeighbors(t *testing.T) {
	dir := t.TempDir()
	current, next, userFile := filepath.Join(dir, "aw"), filepath.Join(dir, "download"), filepath.Join(dir, "user-data")
	for p, data := range map[string]string{current: "serving", next: "new", userFile: "keep"} {
		if err := os.WriteFile(p, []byte(data), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(userFile, current+".new"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current+".old", []byte("keep-old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(binaryReplacement{CurrentPath: current, CandidatePath: next}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{current: "new", userFile: "keep", current + ".old": "keep-old"} {
		got, err := os.ReadFile(p)
		if err != nil || string(got) != want {
			t.Errorf("%s = %q %v; want %q", p, got, err, want)
		}
	}
}

func TestUpgradeDigestRefusalKeepsServingBinary(t *testing.T) {
	oldVersion := version
	version = "1.0.0"
	t.Cleanup(func() { version = oldVersion })
	archiveName := fmt.Sprintf("aw_2.0.0_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		archiveName = strings.TrimSuffix(archiveName, "tar.gz") + "zip"
	}
	for _, digestCase := range []string{"missing entry", "mismatch"} {
		t.Run(digestCase, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "aw")
			original := []byte("the serving executable")
			if err := os.WriteFile(destination, original, 0755); err != nil {
				t.Fatal(err)
			}
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/repos/awebai/aw/releases/latest":
					json.NewEncoder(w).Encode(releaseInfo{TagName: "v2.0.0", Assets: []releaseAsset{
						{Name: archiveName, BrowserDownloadURL: server.URL + "/" + archiveName},
						{Name: "checksums.txt", BrowserDownloadURL: server.URL + "/checksums.txt"},
					}})
				case r.URL.Path == "/checksums.txt":
					name := archiveName
					if digestCase == "missing entry" {
						name = "other.tar.gz"
					}
					fmt.Fprintf(w, "%s  %s\n", strings.Repeat("0", 64), name)
				default:
					w.Write([]byte("corrupted archive"))
				}
			}))
			defer server.Close()
			previous := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			t.Cleanup(func() { http.DefaultTransport = previous })
			var out bytes.Buffer
			err := selfUpdateTo(&out, upgradeLocation{APIBase: server.URL, Destination: destination})
			if err == nil || !strings.Contains(err.Error(), archiveName) || !strings.Contains(err.Error(), "Retry aw upgrade") {
				t.Fatalf("missing actionable refusal: %v", err)
			}
			got, readErr := os.ReadFile(destination)
			if readErr != nil || !bytes.Equal(got, original) {
				t.Fatalf("serving executable damaged: %q %v", got, readErr)
			}
		})
	}
}

func TestOversizedArchiveBinaryRefusesBeforeCreatingOutput(t *testing.T) {
	directory := t.TempDir()
	archive := filepath.Join(directory, "large.tar.gz")
	var encoded bytes.Buffer
	compressed := gzip.NewWriter(&encoded)
	writer := tar.NewWriter(compressed)
	if err := writer.WriteHeader(&tar.Header{Name: "aw", Mode: 0755, Size: maxUpgradeBinaryBytes + 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	// The real header declares the oversized file. Its body is unnecessary:
	// refusal must precede opening any output or attempting to consume that body.
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, encoded.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "out")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	err := extractBinary(binaryExtraction{ArchivePath: archive, BinaryName: "aw", Destination: destination})
	if err == nil || !strings.Contains(err.Error(), "size limit") || !strings.Contains(err.Error(), "Retry aw upgrade") {
		t.Fatalf("missing actionable size refusal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, "aw")); !os.IsNotExist(err) {
		t.Fatalf("created output before refusing oversized binary: %v", err)
	}
}

func TestExplicitDowngradeUsesExactReleaseAndWarns(t *testing.T) {
	previous := version
	version = "2.0.0"
	t.Cleanup(func() { version = previous })
	archiveName := fmt.Sprintf("aw_1.0.0_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		archiveName = strings.TrimSuffix(archiveName, "tar.gz") + "zip"
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/awebai/aw/releases/tags/v1.0.0" {
			t.Errorf("downgrade fetched %s instead of requested tag", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(releaseInfo{TagName: "v1.0.0", Assets: []releaseAsset{{Name: archiveName, BrowserDownloadURL: "https://127.0.0.1:1/" + archiveName}}}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	var output bytes.Buffer
	err := selfUpdateTo(&output, upgradeLocation{APIBase: server.URL, Destination: filepath.Join(t.TempDir(), "aw"), RequestedVersion: "1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "checksums.txt is missing") {
		t.Fatalf("explicit version skipped digest refusal: %v", err)
	}
	warning := "Warning: downgrading aw v2.0.0 to v1.0.0 because --version 1.0.0 was explicitly requested. Older releases may contain known vulnerabilities."
	if !strings.Contains(output.String(), warning) {
		t.Fatalf("missing downgrade warning: %s", output.String())
	}
}

func TestAutomaticUpgradeDoesNotSelectOlderRelease(t *testing.T) {
	previous := version
	version = "2.0.0"
	t.Cleanup(func() { version = previous })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/awebai/aw/releases/latest" {
			t.Errorf("unexpected artifact request: %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(releaseInfo{TagName: "v1.0.0"}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := selfUpdateTo(&output, upgradeLocation{APIBase: server.URL}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "downgrading") || strings.Contains(output.String(), "Updating") {
		t.Fatalf("selected older release without --version: %s", output.String())
	}
}

func TestChecksumRecordMustHaveExactlyTwoFields(t *testing.T) {
	file := filepath.Join(t.TempDir(), "checksums.txt")
	checksum := strings.Repeat("a", 64)
	for _, content := range []string{checksum + " aw.tgz extra\n", checksum + " aw.tgz\n" + checksum + " aw.tgz extra\n"} {
		if err := os.WriteFile(file, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := findChecksum(checksumLookup{Path: file, ArtifactName: "aw.tgz"}); err == nil {
			t.Fatalf("accepted malformed checksum record: %s", content)
		}
	}
	if err := os.WriteFile(file, []byte(checksum+" *aw.tgz\n"), 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := findChecksum(checksumLookup{Path: file, ArtifactName: "aw.tgz"})
	if err != nil || actual != checksum {
		t.Fatalf("binary marker checksum refused: %q %v", actual, err)
	}
}
