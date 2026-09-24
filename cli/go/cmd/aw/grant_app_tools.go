package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
)

// Installed-app tool authority for session grants.
//
// A grant can call an installed app tool only if the resident named that exact
// app:verb at mint. The tool definition is snapshotted into the resident home
// at mint and custody signs only from that snapshot, so an edited or updated
// manifest in the worker's plugin directory can never widen or redirect a
// grant. The snapshot is stable authority, not a sandbox: it does not defend
// against hostile processes running as the resident's own user.

const grantAppToolsSnapshotVersion = 1

var grantIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type grantAppToolsSnapshot struct {
	Version int                         `json:"version"`
	GrantID string                      `json:"grant_id"`
	TeamID  string                      `json:"team_id"`
	Apps    map[string]grantAppSnapshot `json:"apps"`
}

type grantAppSnapshot struct {
	ManifestVersion int                `json:"manifest_version"`
	ManifestSHA256  string             `json:"manifest_sha256"`
	App             appmanifest.App    `json:"app"`
	Tools           []appmanifest.Tool `json:"tools"`
}

func grantAppToolsPath(residentHome, grantID string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(grantID))
	if !grantIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid grant id")
	}
	return filepath.Join(residentHome, "grants", id, "app-tools.json"), nil
}

// parseGrantAppToolSpecs parses repeatable --app-tool app:verb values.
func parseGrantAppToolSpecs(values []string) (map[string][]string, error) {
	out := map[string][]string{}
	seen := map[string]bool{}
	for _, value := range values {
		for _, spec := range strings.Split(value, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			app, verb, ok := strings.Cut(spec, ":")
			app, verb = strings.TrimSpace(app), strings.TrimSpace(verb)
			if !ok || app == "" || verb == "" {
				return nil, usageError("--app-tool must be app:verb, got %q", spec)
			}
			if strings.ContainsAny(verb, "*?") || strings.ContainsAny(app, "*?") {
				return nil, usageError("--app-tool does not accept wildcards: %q", spec)
			}
			if seen[app+":"+verb] {
				continue
			}
			seen[app+":"+verb] = true
			out[app] = append(out[app], verb)
		}
	}
	return out, nil
}

// buildGrantAppSnapshots snapshots the exact installed tool definitions named
// at mint. It fails closed on anything ambiguous: duplicate tool names, unsigned
// tools, unknown tools, or an app origin that is a coordination/registry origin.
func buildGrantAppSnapshots(specs map[string][]string, deniedOrigins []string) (map[string]grantAppSnapshot, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	dir, err := pluginDir()
	if err != nil {
		return nil, err
	}
	denied := canonicalOriginSet(deniedOrigins)
	out := map[string]grantAppSnapshot{}
	for app, verbs := range specs {
		name, err := normalizePluginName(app)
		if err != nil {
			return nil, err
		}
		data, err := readFileBounded(manifestPluginManifestPath(dir, name), maxManifestBytes)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, usageError("--app-tool %s: app %q is not installed", app, name)
			}
			return nil, err
		}
		var manifest appmanifest.Manifest
		if err := appmanifest.DecodeSingleJSONStrict(data, &manifest); err != nil {
			return nil, fmt.Errorf("decode manifest for %s: %w", name, err)
		}
		if err := appmanifest.Validate(manifest, reservedRootCommandNames()); err != nil {
			return nil, err
		}
		counts := map[string]int{}
		for _, tool := range manifest.Tools {
			counts[strings.TrimSpace(tool.Name)]++
		}
		origin, err := canonicalAppOrigin(manifest.App.Origin)
		if err != nil {
			return nil, fmt.Errorf("app %s origin: %w", name, err)
		}
		if denied[origin] {
			return nil, usageError("app %s origin %s is a coordination or registry origin; grants cannot sign app requests to it", name, origin)
		}
		sum := sha256.Sum256(data)
		snap := grantAppSnapshot{ManifestVersion: manifest.ManifestVersion, ManifestSHA256: "sha256:" + hex.EncodeToString(sum[:]), App: manifest.App}
		for _, verb := range verbs {
			if counts[verb] == 0 {
				return nil, usageError("--app-tool %s:%s: no such tool", name, verb)
			}
			if counts[verb] > 1 {
				return nil, usageError("--app-tool %s:%s: manifest declares the tool more than once", name, verb)
			}
			for _, tool := range manifest.Tools {
				if strings.TrimSpace(tool.Name) != verb {
					continue
				}
				if strings.TrimSpace(tool.Auth) == "none" {
					return nil, usageError("--app-tool %s:%s is a public tool; it needs no grant", name, verb)
				}
				snap.Tools = append(snap.Tools, tool)
			}
		}
		out[name] = snap
	}
	return out, nil
}

func saveGrantAppToolsSnapshot(residentHome string, snap *grantAppToolsSnapshot) error {
	path, err := grantAppToolsPath(residentHome, snap.GrantID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func loadGrantAppToolsSnapshot(residentHome, grantID string) (*grantAppToolsSnapshot, error) {
	path, err := grantAppToolsPath(residentHome, grantID)
	if err != nil {
		return nil, err
	}
	data, err := readFileBounded(path, maxManifestBytes*8)
	if err != nil {
		return nil, err
	}
	var snap grantAppToolsSnapshot
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snap); err != nil {
		return nil, err
	}
	if snap.Version != grantAppToolsSnapshotVersion || strings.TrimSpace(snap.GrantID) != strings.TrimSpace(grantID) {
		return nil, fmt.Errorf("grant app tool snapshot does not match grant")
	}
	return &snap, nil
}

// canonicalAppOrigin returns scheme://host[:port] with the default port dropped.
func canonicalAppOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("unsupported origin scheme %q", u.Scheme)
	}
	if u.User != nil || u.Host == "" {
		return "", fmt.Errorf("invalid origin %q", raw)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

func canonicalOriginSet(origins []string) map[string]bool {
	out := map[string]bool{}
	for _, raw := range origins {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if origin, err := canonicalAppOrigin(raw); err == nil {
			out[origin] = true
		}
	}
	return out
}

// grantAppDeniedOrigins lists origins a grant must never obtain resident
// signatures for: they accept team-auth envelopes as root/member requests.
func grantAppDeniedOrigins(awebURL, registryURL string) []string {
	return []string{awebURL, registryURL, awid.DefaultAWIDRegistryURL}
}
