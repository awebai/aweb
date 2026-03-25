package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	updateGithubRepo    = "awebai/aw"
	updateGithubAPIBase = "https://api.github.com"
)

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade aw to the latest version",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// No heartbeat for upgrade.
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return selfUpdate(cmd.OutOrStdout(), "")
	},
}

// compareVersions compares two version strings (X.Y.Z format).
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareVersions(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var na, nb int
		if i < len(partsA) {
			na, _ = strconv.Atoi(partsA[i])
		}
		if i < len(partsB) {
			nb, _ = strconv.Atoi(partsB[i])
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

// fetchLatestRelease fetches the latest release info from GitHub.
// apiBase overrides the API base URL for testing; pass "" for production.
func fetchLatestRelease(timeoutSeconds int, apiBase string) (*releaseInfo, error) {
	if apiBase == "" {
		apiBase = updateGithubAPIBase
	}
	url := fmt.Sprintf("%s/repos/%s/releases/latest", apiBase, updateGithubRepo)

	client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var info releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("parsing release info: %w", err)
	}
	return &info, nil
}

// verifyChecksum verifies the SHA256 checksum of a file.
func verifyChecksum(filePath, expected string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actual := fmt.Sprintf("%x", h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

// extractBinary extracts the named binary from a tar.gz or zip archive into destDir.
func extractBinary(archivePath, binaryName, destDir string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractBinaryFromZip(archivePath, binaryName, destDir)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		// Skip entries with path traversal
		clean := filepath.Clean(hdr.Name)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			continue
		}

		// Match the binary name (may be at top level or in a subdirectory)
		if filepath.Base(hdr.Name) == binaryName && hdr.Typeflag == tar.TypeReg {
			destPath := filepath.Join(destDir, binaryName)
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			out.Close()
			if copyErr != nil {
				return copyErr
			}
			return nil
		}
	}

	return fmt.Errorf("binary %q not found in archive", binaryName)
}

func extractBinaryFromZip(archivePath, binaryName, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// Skip entries with path traversal
		clean := filepath.Clean(f.Name)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			continue
		}

		if filepath.Base(f.Name) == binaryName || filepath.Base(f.Name) == binaryName+".exe" {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			destPath := filepath.Join(destDir, filepath.Base(f.Name))
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, f.Mode())
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, rc)
			out.Close()
			if copyErr != nil {
				return copyErr
			}
			return nil
		}
	}
	return fmt.Errorf("binary %q not found in archive", binaryName)
}

// replaceBinary performs an atomic-ish swap: write .new, rename current → .old, rename .new → current, remove .old.
func replaceBinary(currentPath, newPath string) error {
	newDest := currentPath + ".new"
	oldDest := currentPath + ".old"

	src, err := os.Open(newPath)
	if err != nil {
		return err
	}
	defer src.Close()

	// Get permissions from current binary
	info, err := os.Stat(currentPath)
	if err != nil {
		return err
	}

	dst, err := os.OpenFile(newDest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	dst.Close()

	// Swap: current → .old, .new → current
	if err := os.Rename(currentPath, oldDest); err != nil {
		return fmt.Errorf("backing up current binary: %w", err)
	}
	if err := os.Rename(newDest, currentPath); err != nil {
		// Try to restore
		_ = os.Rename(oldDest, currentPath)
		return fmt.Errorf("replacing binary: %w", err)
	}

	// Clean up .old
	_ = os.Remove(oldDest)

	return nil
}

// resignMacOS re-signs the binary on macOS (ad-hoc signature).
func resignMacOS(binaryPath string) {
	if runtime.GOOS != "darwin" {
		return
	}
	_ = exec.Command("codesign", "--remove-signature", binaryPath).Run()
	_ = exec.Command("codesign", "--force", "--sign", "-", binaryPath).Run()
}

// selfUpdate performs the full update flow. apiBase overrides the GitHub API URL for testing; pass "" for production.
func selfUpdate(w io.Writer, apiBase string) error {
	currentVersion := strings.TrimPrefix(version, "v")

	if currentVersion == "dev" || currentVersion == "" {
		fmt.Fprintln(w, "Skipping upgrade: running a dev build. Install a release build to use upgrade.")
		return nil
	}

	fmt.Fprintf(w, "Checking for updates...\n")

	info, err := fetchLatestRelease(30, apiBase)
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	latestVersion := strings.TrimPrefix(info.TagName, "v")

	if compareVersions(currentVersion, latestVersion) >= 0 {
		fmt.Fprintf(w, "aw v%s is already the latest version.\n", currentVersion)
		return nil
	}

	fmt.Fprintf(w, "Updating aw v%s → v%s...\n", currentVersion, latestVersion)

	// Determine platform archive name
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	archiveName := fmt.Sprintf("aw_%s_%s_%s.%s", latestVersion, goos, goarch, ext)

	// Find download URLs
	var archiveURL, checksumsURL string
	for _, a := range info.Assets {
		if a.Name == archiveName {
			archiveURL = a.BrowserDownloadURL
		}
		if a.Name == "checksums.txt" {
			checksumsURL = a.BrowserDownloadURL
		}
	}

	if archiveURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (expected %s)", goos, goarch, archiveName)
	}

	// Download to temp dir
	tmpDir, err := os.MkdirTemp("", "aw-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, archiveName)
	if err := downloadFile(archivePath, archiveURL); err != nil {
		return fmt.Errorf("downloading archive: %w", err)
	}

	// Verify checksum if available
	if checksumsURL != "" {
		checksumsPath := filepath.Join(tmpDir, "checksums.txt")
		if err := downloadFile(checksumsPath, checksumsURL); err != nil {
			return fmt.Errorf("downloading checksums: %w", err)
		}

		expected, err := findChecksum(checksumsPath, archiveName)
		if err != nil {
			return fmt.Errorf("reading checksums: %w", err)
		}

		if err := verifyChecksum(archivePath, expected); err != nil {
			return err
		}
	}

	// Extract binary
	extractDir := filepath.Join(tmpDir, "extracted")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return err
	}

	binaryName := "aw"
	if goos == "windows" {
		binaryName = "aw.exe"
	}

	if err := extractBinary(archivePath, binaryName, extractDir); err != nil {
		return fmt.Errorf("extracting binary: %w", err)
	}

	// Get current binary path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding current binary: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("resolving binary path: %w", err)
	}

	// Replace binary
	newBinaryPath := filepath.Join(extractDir, binaryName)
	if err := replaceBinary(exePath, newBinaryPath); err != nil {
		return fmt.Errorf("replacing binary: %w", err)
	}

	// Re-sign on macOS
	resignMacOS(exePath)

	fmt.Fprintf(w, "Updated aw v%s → v%s\n", currentVersion, latestVersion)
	return nil
}

// downloadFile downloads a URL to a local file.
func downloadFile(destPath, rawURL string) error {
	if !strings.HasPrefix(rawURL, "https://") {
		return fmt.Errorf("refusing non-HTTPS download URL: %s", rawURL)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

// findChecksum looks up the expected checksum for a file in a checksums.txt file.
func findChecksum(checksumsPath, filename string) (string, error) {
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found", filename)
}

// checkLatestVersion checks if a newer version is available and prints a hint.
// Errors are silently ignored. apiBase overrides the GitHub API URL for testing.
func checkLatestVersion(w io.Writer, apiBase string) {
	currentVersion := strings.TrimPrefix(version, "v")
	if currentVersion == "dev" || currentVersion == "" {
		return
	}

	info, err := fetchLatestRelease(3, apiBase)
	if err != nil {
		return
	}

	latestVersion := strings.TrimPrefix(info.TagName, "v")
	if compareVersions(currentVersion, latestVersion) < 0 {
		fmt.Fprintf(w, "Upgrade available: v%s → v%s (run `aw upgrade`)\n", currentVersion, latestVersion)
	}
}
