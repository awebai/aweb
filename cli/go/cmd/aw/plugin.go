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
	"strings"
	"time"

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

type pluginListOutput struct {
	Plugins []pluginListItem `json:"plugins"`
}

type pluginListItem struct {
	Name       string            `json:"name"`
	Path       string            `json:"path"`
	Provenance *pluginProvenance `json:"provenance,omitempty"`
}

type pluginProvenance struct {
	AppName         string `json:"app_name"`
	AppID           string `json:"app_id,omitempty"`
	ManifestVersion string `json:"manifest_version,omitempty"`
	AppVersion      string `json:"app_version,omitempty"`
	Origin          string `json:"origin,omitempty"`
	Source          string `json:"source,omitempty"`
	Digest          string `json:"digest,omitempty"`
	InstalledAt     string `json:"installed_at,omitempty"`
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

func init() {
	pluginInstallCmd.Flags().StringVar(&pluginInstallAppID, "app-id", "", "App id to record in plugin provenance")
	pluginInstallCmd.Flags().StringVar(&pluginInstallManifestVersion, "manifest-version", "", "Manifest version to record in plugin provenance")
	pluginInstallCmd.Flags().StringVar(&pluginInstallAppVersion, "app-version", "", "App version to record in plugin provenance")
	pluginInstallCmd.Flags().StringVar(&pluginInstallOrigin, "origin", "", "App origin to record in plugin provenance")

	pluginCmd.GroupID = groupUtility
	pluginCmd.AddCommand(pluginListCmd, pluginInstallCmd, pluginRemoveCmd)
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

func runPluginInstall(cmd *cobra.Command, args []string) error {
	source := strings.TrimSpace(args[0])
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
	dir, err := pluginDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
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
		plugins = append(plugins, pluginListItem{Name: name, Path: path, Provenance: provenance})
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
	out := v.(pluginInstallOutput)
	return fmt.Sprintf("Installed plugin %s -> %s\n", out.Name, out.Path)
}

func formatPluginRemove(v any) string {
	out := v.(pluginRemoveOutput)
	return fmt.Sprintf("Removed plugin %s (%s)\n", out.Name, out.Path)
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
	path, ok, err := resolveTrustedExternalPlugin(commandName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	if !ok {
		return 0, false
	}
	return runExternalPlugin(path, args[commandIndex+1:]), true
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
		case "--json", "--debug":
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

func resolveTrustedExternalPlugin(name string) (string, bool, error) {
	dir, err := pluginDir()
	if err != nil {
		debugLog("resolve plugin dir: %v", err)
		return "", false, nil
	}
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
	loadDotenvBestEffort()
	awHome, _ := awHomeDir()
	helper := os.Args[0]
	if abs, err := filepath.Abs(helper); err == nil {
		helper = abs
	}
	values := map[string]string{
		"AW_HOME":   awHome,
		"AW_HELPER": helper,
	}
	if sel, err := resolveSelectionForDir(""); err == nil && sel != nil {
		values["AW_DID"] = strings.TrimSpace(sel.DID)
		values["AW_TEAM"] = strings.TrimSpace(sel.TeamID)
		values["AW_SERVER"] = strings.TrimSpace(sel.BaseURL)
	} else {
		values["AW_DID"] = ""
		values["AW_TEAM"] = ""
		values["AW_SERVER"] = ""
	}
	env := os.Environ()
	for key, value := range values {
		env = setEnvValue(env, key, value)
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
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	reserved := map[string]struct{}{
		"help": {},
	}
	for _, cmd := range rootCmd.Commands() {
		if cmd == nil {
			continue
		}
		if n := strings.TrimSpace(cmd.Name()); n != "" {
			reserved[n] = struct{}{}
		}
		for _, alias := range cmd.Aliases {
			if alias = strings.TrimSpace(alias); alias != "" {
				reserved[alias] = struct{}{}
			}
		}
	}
	_, ok := reserved[name]
	return ok
}
