package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/awebai/aw/internal/appmanifest"
	"github.com/spf13/cobra"
)

const pluginNamePrefix = "aw-"

var (
	pluginInstallAppID           string
	pluginInstallManifestVersion string
	pluginInstallAppVersion      string
	pluginInstallOrigin          string
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage aw plugins",
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed plugins",
	RunE:  runPluginList,
}

var pluginInstallCmd = &cobra.Command{
	Use:   "install <source>",
	Short: "Install a plugin into the trusted aw plugin directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginInstall,
}

var pluginRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an installed plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginRemove,
}

var pluginUpdateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Update an installed manifest plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginUpdate,
}

var pluginReservedNamesCmd = &cobra.Command{
	Use:   "reserved-names",
	Short: "Emit reserved top-level aw app ids",
	Args:  cobra.NoArgs,
	RunE:  runPluginReservedNames,
}

type pluginListOutput struct {
	Plugins []pluginListItem `json:"plugins"`
}

type pluginListItem struct {
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Path         string            `json:"path"`
	ManifestPath string            `json:"manifest_path,omitempty"`
	Provenance   *pluginProvenance `json:"provenance,omitempty"`
}

type pluginProvenance struct {
	AppName         string `json:"app_name"`
	AppID           string `json:"app_id,omitempty"`
	ManifestVersion string `json:"manifest_version,omitempty"`
	AppVersion      string `json:"app_version,omitempty"`
	Origin          string `json:"origin,omitempty"`
	Source          string `json:"source,omitempty"`
	ManifestURL     string `json:"manifest_url,omitempty"`
	Digest          string `json:"digest,omitempty"`
	InstalledAt     string `json:"installed_at,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

type pluginInstallOutput struct {
	Name       string            `json:"name"`
	Path       string            `json:"path"`
	Provenance *pluginProvenance `json:"provenance,omitempty"`
}

type pluginRemoveOutput struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type reservedAppIDsOutput struct {
	Schema         string   `json:"schema"`
	ReservedAppIDs []string `json:"reserved_app_ids"`
}

func init() {
	pluginInstallCmd.Flags().StringVar(&pluginInstallAppID, "app-id", "", "App id to record in plugin provenance")
	pluginInstallCmd.Flags().StringVar(&pluginInstallManifestVersion, "manifest-version", "", "Manifest version to record in plugin provenance")
	pluginInstallCmd.Flags().StringVar(&pluginInstallAppVersion, "app-version", "", "App version to record in plugin provenance")
	pluginInstallCmd.Flags().StringVar(&pluginInstallOrigin, "origin", "", "App origin to record in plugin provenance")

	pluginCmd.GroupID = groupUtility
	pluginCmd.AddCommand(pluginListCmd, pluginInstallCmd, pluginRemoveCmd, pluginUpdateCmd, pluginReservedNamesCmd)
	rootCmd.AddCommand(pluginCmd)
}

func runPluginList(cmd *cobra.Command, args []string) error {
	plugins, err := installedPlugins()
	if err != nil {
		return err
	}
	printOutput(pluginListOutput{Plugins: plugins}, formatPluginList)
	return nil
}

func runPluginReservedNames(cmd *cobra.Command, args []string) error {
	printOutput(reservedAppIDsArtifact(), formatReservedAppIDs)
	return nil
}

func runPluginInstall(cmd *cobra.Command, args []string) error {
	source := strings.TrimSpace(args[0])
	dir, err := pluginDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if isManifestInstallSource(source) {
		out, err := installManifestPlugin(source, dir)
		if err != nil {
			return err
		}
		printOutput(out, formatPluginInstall)
		return nil
	}
	name, err := pluginNameFromSource(source)
	if err != nil {
		return err
	}
	if isReservedRootCommandName(name) {
		return usageError("plugin name %q is reserved built-in command or alias", name)
	}
	if err := validatePluginName(name); err != nil {
		return err
	}
	if manifestPluginExists(dir, name) {
		return fmt.Errorf("plugin %q is already installed as a manifest app", name)
	}
	dest := filepath.Join(dir, pluginExecutableName(name))
	provenancePath := pluginProvenancePath(dir, name)
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("plugin %q is already installed at %s", name, dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(provenancePath); err == nil {
		return fmt.Errorf("plugin %q provenance already exists at %s", name, provenancePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	digest, err := installPluginSource(source, dest)
	if err != nil {
		return err
	}
	provenance := pluginProvenance{
		AppName:         name,
		AppID:           strings.TrimSpace(pluginInstallAppID),
		ManifestVersion: strings.TrimSpace(pluginInstallManifestVersion),
		AppVersion:      strings.TrimSpace(pluginInstallAppVersion),
		Origin:          strings.TrimSpace(pluginInstallOrigin),
		Source:          source,
		Digest:          digest,
		InstalledAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := savePluginProvenance(provenancePath, &provenance); err != nil {
		_ = os.Remove(dest)
		return err
	}
	printOutput(pluginInstallOutput{Name: name, Path: dest, Provenance: &provenance}, formatPluginInstall)
	return nil
}

func runPluginRemove(cmd *cobra.Command, args []string) error {
	name, err := normalizePluginName(args[0])
	if err != nil {
		return err
	}
	dir, err := pluginDir()
	if err != nil {
		return err
	}
	if manifestPluginExists(dir, name) {
		path := manifestPluginDir(dir, name)
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		printOutput(pluginRemoveOutput{Name: name, Path: path}, formatPluginRemove)
		return nil
	}
	path := filepath.Join(dir, pluginExecutableName(name))
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("plugin %q is not installed", name)
		}
		return err
	}
	if err := os.Remove(pluginProvenancePath(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	printOutput(pluginRemoveOutput{Name: name, Path: path}, formatPluginRemove)
	return nil
}

func runPluginUpdate(cmd *cobra.Command, args []string) error {
	name, err := normalizePluginName(args[0])
	if err != nil {
		return err
	}
	dir, err := pluginDir()
	if err != nil {
		return err
	}
	if !manifestPluginExists(dir, name) {
		return fmt.Errorf("plugin %q is not an installed manifest app", name)
	}
	provenance, err := loadPluginProvenance(manifestPluginProvenancePath(dir, name))
	if err != nil {
		return err
	}
	if provenance == nil || strings.TrimSpace(provenance.ManifestURL) == "" {
		return fmt.Errorf("plugin %q is missing manifest provenance", name)
	}
	out, err := installOrUpdateManifestPlugin(provenance.ManifestURL, dir, true)
	if err != nil {
		return err
	}
	printOutput(out, formatPluginInstall)
	return nil
}

func installedPlugins() ([]pluginListItem, error) {
	dir, err := pluginDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	plugins := make([]pluginListItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			name := strings.TrimSpace(entry.Name())
			manifestPath := manifestPluginManifestPath(dir, name)
			if _, err := os.Stat(manifestPath); err != nil {
				continue
			}
			provenance, err := loadPluginProvenance(manifestPluginProvenancePath(dir, name))
			if err != nil {
				return nil, err
			}
			plugins = append(plugins, pluginListItem{Name: name, Kind: "manifest", Path: filepath.Join(dir, name), ManifestPath: manifestPath, Provenance: provenance})
			continue
		}
		name, ok := pluginNameFromExecutable(entry.Name())
		if !ok {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
			continue
		}
		provenance, err := loadPluginProvenance(pluginProvenancePath(dir, name))
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, pluginListItem{Name: name, Kind: "external", Path: path, Provenance: provenance})
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].Name < plugins[j].Name })
	return plugins, nil
}

func formatPluginList(v any) string {
	out := v.(pluginListOutput)
	if len(out.Plugins) == 0 {
		return "No plugins installed.\n"
	}
	var sb strings.Builder
	sb.WriteString("Installed plugins:\n")
	for _, plugin := range out.Plugins {
		extra := ""
		if plugin.Provenance != nil && strings.TrimSpace(plugin.Provenance.Origin) != "" {
			extra = "\t" + strings.TrimSpace(plugin.Provenance.Origin)
		}
		sb.WriteString(fmt.Sprintf("  %s\t%s%s\n", plugin.Name, plugin.Path, extra))
	}
	return sb.String()
}

func formatPluginInstall(v any) string {
	out, ok := v.(pluginInstallOutput)
	if !ok {
		if ptr, ok := v.(*pluginInstallOutput); ok && ptr != nil {
			out = *ptr
		}
	}
	return fmt.Sprintf("Installed plugin %s -> %s\n", out.Name, out.Path)
}

func formatPluginRemove(v any) string {
	out := v.(pluginRemoveOutput)
	return fmt.Sprintf("Removed plugin %s (%s)\n", out.Name, out.Path)
}

func formatReservedAppIDs(v any) string {
	out := v.(reservedAppIDsOutput)
	return strings.Join(out.ReservedAppIDs, "\n") + "\n"
}

func pluginNameFromSource(source string) (string, error) {
	if strings.TrimSpace(source) == "" {
		return "", usageError("plugin source is required")
	}
	nameSource := source
	if u, err := url.Parse(source); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		nameSource = u.Path
	}
	base := filepath.Base(strings.TrimSpace(nameSource))
	return normalizePluginName(base)
}

func normalizePluginName(raw string) (string, error) {
	name := strings.TrimSpace(filepath.Base(raw))
	if runtime.GOOS == "windows" {
		name = strings.TrimSuffix(name, ".exe")
	} else {
		name = strings.TrimSuffix(name, ".exe")
	}
	name = strings.TrimPrefix(name, pluginNamePrefix)
	if err := validatePluginName(name); err != nil {
		return "", err
	}
	return name, nil
}

func validatePluginName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return usageError("plugin name is required")
	}
	if strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, "-") || strings.Contains(name, "..") {
		return usageError("invalid plugin name %q", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return usageError("invalid plugin name %q", name)
		}
	}
	return nil
}

func pluginExecutableName(name string) string {
	base := pluginNamePrefix + name
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func pluginNameFromExecutable(base string) (string, bool) {
	base = strings.TrimSpace(base)
	if runtime.GOOS == "windows" {
		base = strings.TrimSuffix(base, ".exe")
	} else {
		base = strings.TrimSuffix(base, ".exe")
	}
	if !strings.HasPrefix(base, pluginNamePrefix) {
		return "", false
	}
	name := strings.TrimPrefix(base, pluginNamePrefix)
	if err := validatePluginName(name); err != nil {
		return "", false
	}
	return name, true
}

func isManifestInstallSource(source string) bool {
	u, err := url.Parse(strings.TrimSpace(source))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

func installManifestPlugin(source, dir string) (*pluginInstallOutput, error) {
	return installOrUpdateManifestPlugin(source, dir, false)
}

func installOrUpdateManifestPlugin(source, dir string, update bool) (*pluginInstallOutput, error) {
	manifestURL, err := manifestURLForSource(source)
	if err != nil {
		return nil, err
	}
	manifestBytes, digest, err := fetchManifest(manifestURL)
	if err != nil {
		return nil, err
	}
	var manifest appmanifest.Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	reserved := reservedRootCommandNames()
	if err := appmanifest.Validate(manifest, reserved); err != nil {
		return nil, err
	}
	claimedManifestURL, err := manifestURLForSource(manifest.App.Origin)
	if err != nil {
		return nil, err
	}
	if claimedManifestURL != manifestURL {
		return nil, fmt.Errorf("manifest fetched from %s claims origin %s (expected manifest URL %s)", manifestURL, manifest.App.Origin, claimedManifestURL)
	}
	name, err := normalizePluginName(manifest.App.ID)
	if err != nil {
		return nil, err
	}
	if isReservedRootCommandName(name) {
		return nil, usageError("plugin name %q is reserved built-in command or alias", name)
	}
	if externalPluginExists(dir, name) {
		return nil, fmt.Errorf("plugin %q is already installed as an external plugin", name)
	}
	appDir := manifestPluginDir(dir, name)
	if !update {
		if _, err := os.Stat(appDir); err == nil {
			return nil, fmt.Errorf("plugin %q is already installed at %s", name, appDir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		return nil, err
	}
	manifestPath := manifestPluginManifestPath(dir, name)
	provenancePath := manifestPluginProvenancePath(dir, name)
	if err := os.WriteFile(manifestPath+".tmp", manifestBytes, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(manifestPath+".tmp", manifestPath); err != nil {
		_ = os.Remove(manifestPath + ".tmp")
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	installedAt := now
	if update {
		if existing, err := loadPluginProvenance(provenancePath); err == nil && existing != nil && strings.TrimSpace(existing.InstalledAt) != "" {
			installedAt = existing.InstalledAt
		}
	}
	provenance := pluginProvenance{
		AppName:         name,
		AppID:           strings.TrimSpace(manifest.App.ID),
		ManifestVersion: strconv.Itoa(manifest.ManifestVersion),
		AppVersion:      strings.TrimSpace(manifest.App.Version),
		Origin:          strings.TrimSpace(manifest.App.Origin),
		Source:          source,
		ManifestURL:     manifestURL,
		Digest:          digest,
		InstalledAt:     installedAt,
		UpdatedAt:       now,
	}
	if err := savePluginProvenance(provenancePath, &provenance); err != nil {
		return nil, err
	}
	return &pluginInstallOutput{Name: name, Path: appDir, Provenance: &provenance}, nil
}

func manifestURLForSource(source string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(source))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid manifest source %q", source)
	}
	if strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/.well-known/aweb-app.json") {
		u.RawQuery = ""
		u.Fragment = ""
		return u.String(), nil
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/.well-known/aweb-app.json"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func fetchManifest(manifestURL string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return nil
			}
			origin := via[0].URL
			if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
				return fmt.Errorf("manifest fetch cross-origin redirect from %s://%s to %s://%s", origin.Scheme, origin.Host, req.URL.Scheme, req.URL.Host)
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("fetch manifest: HTTP %d", resp.StatusCode)
	}
	h := sha256.New()
	var b strings.Builder
	if _, err := io.Copy(io.MultiWriter(&b, h), io.LimitReader(resp.Body, 10<<20)); err != nil {
		return nil, "", err
	}
	return []byte(b.String()), "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func manifestPluginDir(dir, name string) string {
	return filepath.Join(dir, name)
}

func manifestPluginManifestPath(dir, name string) string {
	return filepath.Join(manifestPluginDir(dir, name), "manifest.json")
}

func manifestPluginProvenancePath(dir, name string) string {
	return filepath.Join(manifestPluginDir(dir, name), "provenance.json")
}

func manifestPluginExists(dir, name string) bool {
	info, err := os.Stat(manifestPluginManifestPath(dir, name))
	return err == nil && !info.IsDir()
}

func externalPluginExists(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, pluginExecutableName(name)))
	return err == nil && !info.IsDir()
}

func installPluginSource(source, dest string) (string, error) {
	var reader io.ReadCloser
	var mode os.FileMode = 0o755
	if u, err := url.Parse(source); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return "", fmt.Errorf("download plugin: HTTP %d", resp.StatusCode)
		}
		reader = resp.Body
	} else {
		f, err := os.Open(source)
		if err != nil {
			return "", err
		}
		if info, err := f.Stat(); err == nil {
			if info.IsDir() {
				_ = f.Close()
				return "", fmt.Errorf("plugin source %s is a directory", source)
			}
			if info.Mode()&0o111 != 0 {
				mode = info.Mode().Perm()
			}
		}
		reader = f
	}
	defer reader.Close()

	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode|0o111)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := copyWithDigest(out, io.LimitReader(reader, 100<<20), h)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return "", closeErr
	}
	if err := os.Chmod(tmp, mode|0o111); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func copyWithDigest(dst io.Writer, src io.Reader, h hash.Hash) (int64, error) {
	return io.Copy(io.MultiWriter(dst, h), src)
}

func pluginProvenancePath(dir, name string) string {
	return filepath.Join(dir, pluginExecutableName(name)+".provenance.json")
}

func savePluginProvenance(path string, provenance *pluginProvenance) error {
	if provenance == nil {
		return fmt.Errorf("plugin provenance is required")
	}
	data, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func loadPluginProvenance(path string) (*pluginProvenance, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var provenance pluginProvenance
	if err := json.Unmarshal(data, &provenance); err != nil {
		return nil, fmt.Errorf("load plugin provenance %s: %w", path, err)
	}
	return &provenance, nil
}

func pluginDir() (string, error) {
	home, err := awHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "plugins"), nil
}

func awHomeDir() (string, error) {
	if v := strings.TrimSpace(os.Getenv("AW_HOME")); v != "" {
		return filepath.Clean(v), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aw"), nil
}

func dispatchPluginIfRequested(args []string) (int, bool) {
	commandName, commandIndex := firstNonFlagArg(args)
	if commandName == "" || commandIndex < 0 {
		return 0, false
	}
	if isReservedRootCommandName(commandName) {
		return 0, false
	}
	if err := validatePluginName(commandName); err != nil {
		return 0, false
	}
	resolution, err := resolveTrustedPluginCommand(commandName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	switch resolution.Kind {
	case pluginResolutionManifest:
		return dispatchInstalledManifestPlugin(commandName, args[commandIndex+1:])
	case pluginResolutionExternal:
		return runExternalPlugin(resolution.Path, args[commandIndex+1:]), true
	default:
		return 0, false
	}
}

func firstNonFlagArg(args []string) (string, int) {
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1], i + 1
			}
			return "", -1
		}
		if strings.HasPrefix(arg, "--server-name=") {
			continue
		}
		switch arg {
		case "--json", "--debug", "--trace":
			continue
		case "--server-name":
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return "", -1
		}
		return arg, i
	}
	return "", -1
}

func dispatchInstalledManifestPlugin(name string, args []string) (int, bool) {
	dir, err := pluginDir()
	if err != nil {
		debugLog("resolve plugin dir: %v", err)
		return 0, false
	}
	manifestPath := manifestPluginManifestPath(dir, name)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, false
		}
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	var manifest appmanifest.Manifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&manifest); err != nil {
		fmt.Fprintf(os.Stderr, "decode manifest %s: %v\n", manifestPath, err)
		return 1, true
	}
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintf(os.Stderr, "missing verb for app %q\n", name)
		return 1, true
	}
	verb := strings.TrimSpace(args[0])
	parsedArgs, rawBody, err := parseManifestDispatchArgs(args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	spec, err := appmanifest.Interpret(appmanifest.InterpretRequest{
		Manifest:      manifest,
		Verb:          verb,
		Args:          parsedArgs,
		RawBody:       rawBody,
		ReservedNames: reservedRootCommandNames(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	parsedURL, err := url.Parse(spec.URL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	headers := make(http.Header)
	for key, value := range spec.Headers {
		headers.Set(key, value)
	}
	result, err := executeSignedIDRequest(spec.Method, parsedURL, identity, spec.Body, headers, map[string]any{}, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	if _, err := os.Stdout.Write(result.Body); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	if result.Status >= 400 {
		return 1, true
	}
	return 0, true
}

func parseManifestDispatchArgs(args []string) (map[string]any, []byte, error) {
	out := map[string]any{}
	var rawBody []byte
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}
		if !strings.HasPrefix(arg, "--") {
			return nil, nil, usageError("unexpected positional argument %q", arg)
		}
		nameValue := strings.TrimPrefix(arg, "--")
		name, value, hasValue := strings.Cut(nameValue, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, nil, usageError("empty flag name")
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil, nil, usageError("missing value for --%s", name)
			}
			i++
			value = args[i]
		}
		if name == "body-file" {
			data, err := readManifestBodyFile(value)
			if err != nil {
				return nil, nil, err
			}
			rawBody = data
			continue
		}
		addManifestArgValue(out, name, value)
	}
	return out, rawBody, nil
}

func readManifestBodyFile(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, usageError("--body-file requires a path or -")
	}
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func addManifestArgValue(out map[string]any, name, value string) {
	if existing, ok := out[name]; ok {
		switch v := existing.(type) {
		case []any:
			out[name] = append(v, value)
		default:
			out[name] = []any{v, value}
		}
		return
	}
	out[name] = value
}

type pluginResolutionKind string

const (
	pluginResolutionNone     pluginResolutionKind = ""
	pluginResolutionManifest pluginResolutionKind = "manifest"
	pluginResolutionExternal pluginResolutionKind = "external"
)

type pluginResolution struct {
	Kind pluginResolutionKind
	Path string
}

func resolveTrustedPluginCommand(name string) (pluginResolution, error) {
	dir, err := pluginDir()
	if err != nil {
		debugLog("resolve plugin dir: %v", err)
		return pluginResolution{}, nil
	}
	if manifestPluginExists(dir, name) {
		return pluginResolution{Kind: pluginResolutionManifest, Path: manifestPluginManifestPath(dir, name)}, nil
	}
	path, ok, err := resolveTrustedExternalPluginInDir(dir, name)
	if err != nil || !ok {
		return pluginResolution{}, err
	}
	return pluginResolution{Kind: pluginResolutionExternal, Path: path}, nil
}

func resolveTrustedExternalPlugin(name string) (string, bool, error) {
	dir, err := pluginDir()
	if err != nil {
		debugLog("resolve plugin dir: %v", err)
		return "", false, nil
	}
	return resolveTrustedExternalPluginInDir(dir, name)
}

func resolveTrustedExternalPluginInDir(dir, name string) (string, bool, error) {
	path := filepath.Join(dir, pluginExecutableName(name))
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	if info.IsDir() {
		return "", false, fmt.Errorf("plugin %q resolves to a directory: %s", name, path)
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return "", false, fmt.Errorf("plugin %q is not executable: %s", name, path)
	}
	return path, true, nil
}

func runExternalPlugin(path string, args []string) int {
	cmd := exec.Command(path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = pluginEnv()
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "run plugin %s: %v\n", path, err)
		return 1
	}
	return 0
}

func pluginEnv() []string {
	awHome, _ := awHomeDir()
	helper := os.Args[0]
	if abs, err := filepath.Abs(helper); err == nil {
		helper = abs
	}
	values := map[string]string{
		"AW_DID":    "",
		"AW_TEAM":   "",
		"AW_SERVER": "",
		"AW_HOME":   awHome,
		"AW_HELPER": helper,
	}
	if sel, err := resolveSelectionForDir(""); err == nil && sel != nil {
		values["AW_DID"] = strings.TrimSpace(sel.DID)
		values["AW_TEAM"] = strings.TrimSpace(sel.TeamID)
		values["AW_SERVER"] = strings.TrimSpace(sel.BaseURL)
	}
	env := allowlistedPluginBaseEnv()
	for key, value := range values {
		env = setEnvValue(env, key, value)
	}
	return env
}

func allowlistedPluginBaseEnv() []string {
	keys := []string{"PATH", "HOME", "TMPDIR"}
	if runtime.GOOS == "windows" {
		keys = append(keys, "SystemRoot")
	}
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func setEnvValue(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func isReservedRootCommandName(name string) bool {
	return reservedRootCommandNames()[strings.TrimSpace(name)]
}

func reservedAppIDsArtifact() reservedAppIDsOutput {
	return reservedAppIDsOutput{
		Schema:         "aweb.reserved-app-ids.v1",
		ReservedAppIDs: sortedReservedRootCommandNames(),
	}
}

func sortedReservedRootCommandNames() []string {
	reserved := reservedRootCommandNames()
	names := make([]string, 0, len(reserved))
	for name := range reserved {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func reservedRootCommandNames() map[string]bool {
	rootCmd.InitDefaultCompletionCmd()
	reserved := map[string]bool{
		"help": true,
	}
	for _, cmd := range rootCmd.Commands() {
		if cmd == nil {
			continue
		}
		if n := strings.TrimSpace(cmd.Name()); n != "" {
			reserved[n] = true
		}
		for _, alias := range cmd.Aliases {
			if alias = strings.TrimSpace(alias); alias != "" {
				reserved[alias] = true
			}
		}
	}
	return reserved
}
