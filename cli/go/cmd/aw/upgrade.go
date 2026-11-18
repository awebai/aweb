package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/awebai/aw/internal/atomicfile"
	"github.com/awebai/aw/internal/releaseverify"
	"github.com/awebai/aw/internal/releaseversion"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	updateGithubRepo    = "awebai/aw"
	updateGithubAPIBase = "https://api.github.com"
	updateCheckCacheTTL = time.Hour
)

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type updateCheckCache struct {
	CheckedAt     time.Time `json:"checked_at"`
	LatestVersion string    `json:"latest_version"`
}

var (
	updateCheckAPIBase               = ""
	updateCheckOutput      io.Writer = os.Stderr
	updateCheckNow                   = time.Now
	updateCheckStdoutIsTTY           = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
	updateCheckCachePath             = defaultUpdateCheckCachePath
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade aw to the latest version",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// No heartbeat for upgrade.
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		requested, err := cmd.Flags().GetString("version")
		if err != nil {
			return err
		}
		return selfUpdateTo(cmd.OutOrStdout(), upgradeLocation{RequestedVersion: requested})
	},
}

func init() {
	upgradeCmd.Flags().String("version", "", "Install an exact released version; explicitly selecting an older version permits a downgrade with a warning")
}

// compareVersions compares final and RC releases. Unknown versions do not
// establish that an update is newer.
func compareVersions(a, b string) int {
	order, valid := releaseversion.Compare(a, b)
	if !valid {
		return 0
	}
	return order
}

// fetchLatestRelease fetches the latest release info from GitHub.
// apiBase overrides the API base URL for testing; pass "" for production.
func fetchLatestRelease(timeoutSeconds int, apiBase string) (*releaseInfo, error) {
	return fetchReleaseInfo(releaseRequest{APIBase: apiBase, Timeout: time.Duration(timeoutSeconds) * time.Second})
}

type releaseRequest struct {
	APIBase string
	Version string
	Timeout time.Duration
}

var exactReleaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$`)

func fetchReleaseInfo(request releaseRequest) (info *releaseInfo, resultErr error) {
	base := request.APIBase
	if base == "" {
		base = updateGithubAPIBase
	}
	route := "/releases/latest"
	if request.Version != "" {
		route = "/releases/tags/" + url.PathEscape("v"+request.Version)
	}
	endpoint := strings.TrimRight(base, "/") + "/repos/" + updateGithubRepo + route
	client := &http.Client{Timeout: request.Timeout}
	response, err := client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("fetching release: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", response.StatusCode)
	}
	info = &releaseInfo{}
	if err := json.NewDecoder(response.Body).Decode(info); err != nil {
		return nil, fmt.Errorf("parsing release info: %w", err)
	}
	return info, nil
}

func defaultUpdateCheckCachePath() string {
	configHome := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if configHome == "" {
		home := strings.TrimSpace(os.Getenv("HOME"))
		if home == "" {
			return ""
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "aw", "update-check.json")
}

func automaticUpdateCheckEnabled() bool {
	return !jsonFlag && strings.TrimSpace(os.Getenv("AW_NO_UPDATE_CHECK")) == "" && updateCheckStdoutIsTTY()
}

func maybeCheckLatestVersion(cmd *cobra.Command) {
	currentVersion := strings.TrimPrefix(version, "v")
	if currentVersion == "dev" || currentVersion == "" {
		return
	}
	if !automaticUpdateCheckEnabled() {
		return
	}
	if shouldSkipUpdateCheck(cmd) {
		return
	}
	checkLatestVersionWithCache(updateCheckOutput, currentVersion, updateCheckAPIBase)
}

func shouldSkipUpdateCheck(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	// Inspection promises no incidental network or cache writes, including in
	// an interactive text-mode invocation of a released binary.
	if isTeamInviteInspectCommand(cmd) {
		return true
	}
	path := strings.Fields(cmd.CommandPath())
	if len(path) == 0 {
		return false
	}
	if path[0] == "aw" {
		path = path[1:]
	}
	if len(path) == 0 {
		return false
	}
	switch path[0] {
	case "run", "heartbeat", "events", "notify", "control", "log", "instructions", "upgrade", "version":
		return true
	case "lock":
		return len(path) > 1 && path[1] == "renew"
	default:
		return false
	}
}

func checkLatestVersionWithCache(w io.Writer, currentVersion, apiBase string) {
	if currentVersion == "" || currentVersion == "dev" {
		return
	}

	if cache, ok := readUpdateCheckCache(); ok && updateCheckNow().Sub(cache.CheckedAt) < updateCheckCacheTTL {
		printUpgradeHintIfNewer(w, currentVersion, cache.LatestVersion)
		return
	}

	done := make(chan string, 1)
	go func() {
		info, err := fetchLatestRelease(3, apiBase)
		if err != nil {
			done <- ""
			return
		}
		done <- strings.TrimPrefix(info.TagName, "v")
	}()

	select {
	case latestVersion := <-done:
		if latestVersion == "" {
			return
		}
		writeUpdateCheckCache(updateCheckCache{
			CheckedAt:     updateCheckNow().UTC(),
			LatestVersion: latestVersion,
		})
		printUpgradeHintIfNewer(w, currentVersion, latestVersion)
	case <-time.After(3 * time.Second):
		return
	}
}

func readUpdateCheckCache() (updateCheckCache, bool) {
	path := updateCheckCachePath()
	if path == "" {
		return updateCheckCache{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return updateCheckCache{}, false
	}
	var cache updateCheckCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return updateCheckCache{}, false
	}
	if cache.CheckedAt.IsZero() || strings.TrimSpace(cache.LatestVersion) == "" {
		return updateCheckCache{}, false
	}
	return cache, true
}

func writeUpdateCheckCache(cache updateCheckCache) {
	path := updateCheckCachePath()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0644)
}

func printUpgradeHintIfNewer(w io.Writer, currentVersion, latestVersion string) {
	latestVersion = strings.TrimPrefix(strings.TrimSpace(latestVersion), "v")
	if latestVersion != "" && compareVersions(currentVersion, latestVersion) < 0 {
		fmt.Fprintf(w, "Upgrade available: v%s → v%s (run `aw upgrade`)\n", currentVersion, latestVersion)
	}
}

// verifyChecksum implements docs/install-integrity.md:6-8.
type archiveChecksum struct {
	Path   string
	SHA256 string
}

func verifyChecksum(checksum archiveChecksum) (resultErr error) {
	filePath, expected := checksum.Path, checksum.SHA256
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actual := fmt.Sprintf("%x", h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s. Retry aw upgrade to download a fresh archive.", filepath.Base(filePath), expected, actual)
	}
	return nil
}

// extractBinary extracts the named binary from a tar.gz or zip archive into destDir.
type binaryExtraction struct {
	ArchivePath string
	BinaryName  string
	Destination string
}

func extractBinary(extraction binaryExtraction) (resultErr error) {
	archivePath, binaryName, destDir := extraction.ArchivePath, extraction.BinaryName, extraction.Destination
	if strings.HasSuffix(archivePath, ".zip") {
		return extractBinaryFromZip(extraction)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, gr.Close()) }()

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
			if hdr.Size < 0 || hdr.Size > maxUpgradeBinaryBytes {
				return fmt.Errorf("%s exceeds the binary size limit. Retry aw upgrade with a supported release.", binaryName)
			}
			destPath := filepath.Join(destDir, binaryName)
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil {
				return errors.Join(copyErr, closeErr)
			}
			return nil
		}
	}

	return fmt.Errorf("binary %q not found in archive", binaryName)
}

func extractBinaryFromZip(extraction binaryExtraction) (resultErr error) {
	archivePath, binaryName, destDir := extraction.ArchivePath, extraction.BinaryName, extraction.Destination
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, r.Close()) }()

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
			defer func() { resultErr = errors.Join(resultErr, rc.Close()) }()

			if !f.Mode().IsRegular() || f.UncompressedSize64 > uint64(maxUpgradeBinaryBytes) {
				return fmt.Errorf("%s is not a supported binary. Retry aw upgrade with a supported release.", binaryName)
			}
			destPath := filepath.Join(destDir, filepath.Base(f.Name))
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, rc)
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil {
				return errors.Join(copyErr, closeErr)
			}
			return nil
		}
	}
	return fmt.Errorf("binary %q not found in archive", binaryName)
}

// replaceBinary stages and syncs the complete executable beside the serving
// path, then renames it over that path in one operation.
type binaryReplacement struct {
	CurrentPath   string
	CandidatePath string
}

func replaceBinary(replacement binaryReplacement) (resultErr error) {
	currentPath, newPath := replacement.CurrentPath, replacement.CandidatePath
	info, err := os.Stat(currentPath)
	if err != nil {
		return err
	}
	f, err := os.Open(newPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	data, err := io.ReadAll(io.LimitReader(f, maxUpgradeBinaryBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxUpgradeBinaryBytes {
		return fmt.Errorf("%s exceeds the binary size limit. Retry aw upgrade with a supported release.", filepath.Base(newPath))
	}
	return atomicfile.Write(currentPath, data, info.Mode().Perm())
}

// macOS signing happens on the private verified candidate before replacement.
func resignMacOS(binaryPath string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if output, err := exec.Command("codesign", "--force", "--sign", "-", binaryPath).CombinedOutput(); err != nil {
		return fmt.Errorf("signing %s: %w (%s). Install the macOS command line tools and retry aw upgrade.", filepath.Base(binaryPath), err, strings.TrimSpace(string(output)))
	}
	return nil
}

const maxUpgradeBinaryBytes int64 = 256 << 20

// selfUpdate performs the full update flow. apiBase overrides the GitHub API URL for testing; pass "" for production.
func selfUpdate(w io.Writer, apiBase string) error {
	return selfUpdateTo(w, upgradeLocation{APIBase: apiBase})
}

// destination is explicit for an isolated real upgrade-path regression harness.
type upgradeLocation struct {
	APIBase          string
	Destination      string
	RequestedVersion string
}

func selfUpdateTo(w io.Writer, location upgradeLocation) error {
	apiBase, destination := location.APIBase, location.Destination
	currentVersion := strings.TrimPrefix(version, "v")

	if currentVersion == "dev" || currentVersion == "" {
		fmt.Fprintln(w, "Skipping upgrade: running a dev build. Install a release build to use upgrade.")
		return nil
	}

	fmt.Fprintf(w, "Checking for updates...\n")

	requested := strings.TrimPrefix(strings.TrimSpace(location.RequestedVersion), "v")
	if requested != "" && !exactReleaseVersion.MatchString(requested) {
		return usageError("invalid release version %q. Use aw upgrade --version X.Y.Z or X.Y.Z-rc.N for a published release", location.RequestedVersion)
	}
	info, err := fetchReleaseInfo(releaseRequest{APIBase: apiBase, Version: requested, Timeout: 30 * time.Second})
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	latestVersion := strings.TrimPrefix(info.TagName, "v")
	if requested != "" && latestVersion != requested {
		return fmt.Errorf("requested aw v%s but release metadata names %s. Retry aw upgrade --version %s when the requested release metadata is available.", requested, info.TagName, requested)
	}
	manifestCurrentVersion := currentVersion
	if requested != "" && compareVersions(requested, currentVersion) < 0 {
		fmt.Fprintf(w, "Warning: downgrading aw v%s to v%s because --version %s was explicitly requested. Older releases may contain known vulnerabilities.\n", currentVersion, requested, requested)
		manifestCurrentVersion = ""
	}

	if requested == "" && compareVersions(currentVersion, latestVersion) >= 0 {
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
	var archiveURL, checksumsURL, manifestURL, signatureURL string
	for _, a := range info.Assets {
		if a.Name == archiveName {
			archiveURL = a.BrowserDownloadURL
		}
		if a.Name == "checksums.txt" {
			checksumsURL = a.BrowserDownloadURL
		}
		if a.Name == "release-manifest.json" {
			manifestURL = a.BrowserDownloadURL
		}
		if a.Name == "release-manifest.sig" {
			signatureURL = a.BrowserDownloadURL
		}
	}

	if archiveURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (expected %s)", goos, goarch, archiveName)
	}

	if checksumsURL == "" {
		return fmt.Errorf("cannot verify %s: checksums.txt is missing. Retry aw upgrade when the release includes checksums.txt.", archiveName)
	}
	if manifestURL == "" && signatureURL == "" {
		fmt.Fprintln(w, "Warning: release-manifest.json is missing; publisher authentication is unavailable. This upgrade requires the release SHA-256 digest. Retry aw upgrade after signed releases are published for publisher verification.")
	}

	// Download to temp dir
	tmpDir, err := os.MkdirTemp("", "aw-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, archiveName)
	if err := downloadFile(releaseDownload{Destination: archivePath, URL: archiveURL}); err != nil {
		return fmt.Errorf("downloading %s: %w. Retry aw upgrade to download a fresh archive.", archiveName, err)
	}

	checksumsPath := filepath.Join(tmpDir, "checksums.txt")
	if err := downloadFile(releaseDownload{Destination: checksumsPath, URL: checksumsURL, Limit: 1 << 20}); err != nil {
		return fmt.Errorf("cannot verify %s: downloading checksums: %w. Retry aw upgrade to download a fresh checksum file.", archiveName, err)
	}
	expected, err := findChecksum(checksumLookup{Path: checksumsPath, ArtifactName: archiveName})
	if err != nil {
		return fmt.Errorf("cannot verify %s: %w. Retry aw upgrade when the release includes a valid checksums.txt.", archiveName, err)
	}
	if err := verifyChecksum(archiveChecksum{Path: archivePath, SHA256: expected}); err != nil {
		return err
	}

	if manifestURL != "" || signatureURL != "" {
		if manifestURL == "" || signatureURL == "" {
			return fmt.Errorf("cannot verify %s: incomplete signed release manifest. Retry aw upgrade after both release-manifest.json and release-manifest.sig are published.", archiveName)
		}
		manifestPath, signaturePath := filepath.Join(tmpDir, "release-manifest.json"), filepath.Join(tmpDir, "release-manifest.sig")
		for file, url := range map[string]string{manifestPath: manifestURL, signaturePath: signatureURL} {
			if err := downloadFile(releaseDownload{Destination: file, URL: url, Limit: 1 << 20}); err != nil {
				return fmt.Errorf("cannot verify %s: %w. Retry aw upgrade to fetch the complete signed release.", archiveName, err)
			}
		}
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		detached, err := os.ReadFile(signaturePath)
		if err != nil {
			return err
		}
		keys, keyErr := releaseverify.PinnedKeys()
		if keyErr != nil {
			return fmt.Errorf("cannot verify %s: %w", archiveName, keyErr)
		}
		artifact, err := releaseverify.Verify(releaseverify.VerificationRequest{ManifestBytes: raw, SignatureBytes: detached, Keys: keys, RequestedVersion: latestVersion, RunningVersion: manifestCurrentVersion, ArtifactName: archiveName})
		if err != nil {
			return err
		}
		if err := releaseverify.VerifyFile(archivePath, artifact); err != nil {
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

	if err := extractBinary(binaryExtraction{ArchivePath: archivePath, BinaryName: binaryName, Destination: extractDir}); err != nil {
		return fmt.Errorf("extracting %s: %w. Retry aw upgrade to download a fresh supported archive.", archiveName, err)
	}

	exePath := destination
	if exePath == "" {
		exePath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("finding current binary: %w", err)
		}
		exePath, err = filepath.EvalSymlinks(exePath)
		if err != nil {
			return fmt.Errorf("resolving binary path: %w", err)
		}
	}

	// Replace binary
	newBinaryPath := filepath.Join(extractDir, binaryName)
	if err := resignMacOS(newBinaryPath); err != nil {
		return err
	}
	if err := replaceBinary(binaryReplacement{CurrentPath: exePath, CandidatePath: newBinaryPath}); err != nil {
		return fmt.Errorf("replacing %s: %w. Close other aw processes and retry aw upgrade; if the OS locks the running executable, install the verified release from another terminal.", filepath.Base(exePath), err)
	}

	fmt.Fprintf(w, "Updated aw v%s → v%s\n", currentVersion, latestVersion)
	return nil
}

// downloadFile downloads a URL to a local file.
type releaseDownload struct {
	Destination string
	URL         string
	Limit       int64
}

func downloadFile(download releaseDownload) (resultErr error) {
	destPath, rawURL, maxBytes := download.Destination, download.URL, download.Limit
	if maxBytes == 0 {
		maxBytes = maxUpgradeBinaryBytes
	}
	if !strings.HasPrefix(rawURL, "https://") {
		return fmt.Errorf("refusing non-HTTPS download URL: %s. Retry aw upgrade from an HTTPS release source.", rawURL)
	}

	client := &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing non-HTTPS download redirect. Retry aw upgrade from a secure release source.")
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many release download redirects. Retry aw upgrade later.")
		}
		return nil
	}}
	resp, err := client.Get(rawURL)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}

	_, copyErr := copyBounded(f, resp.Body, maxBytes, nil)
	closeErr := f.Close()
	return errors.Join(copyErr, closeErr)
}

// findChecksum looks up the expected checksum for a file in a checksums.txt file.
type checksumLookup struct {
	Path         string
	ArtifactName string
}

func findChecksum(lookup checksumLookup) (string, error) {
	checksumsPath, filename := lookup.Path, lookup.ArtifactName
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return "", err
	}

	found := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.TrimPrefix(fields[1], "*") != filename {
			continue
		}
		if len(fields) != 2 {
			return "", fmt.Errorf("invalid checksum record for %s", filename)
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size || found != "" {
			return "", fmt.Errorf("invalid or duplicate checksum for %s", filename)
		}
		found = strings.ToLower(fields[0])
	}
	if found == "" {
		return "", fmt.Errorf("checksum for %s not found", filename)
	}
	return found, nil
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
	printUpgradeHintIfNewer(w, currentVersion, latestVersion)
}
