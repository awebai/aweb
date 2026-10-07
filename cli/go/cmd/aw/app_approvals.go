package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/appmanifest"
	"github.com/awebai/aw/internal/pathpreflight"
)

// The shared manifest store is discovery, not delegation. Only this resident's
// catalog supplies the default authority for a newly minted grant.
type appApprovalCatalog struct {
	Version int               `json:"version"`
	Apps    map[string]string `json:"apps"`
}

func appApprovalsPath(home string) string { return filepath.Join(home, "app-approvals.json") }

func loadAppApprovals(home string) (*appApprovalCatalog, error) {
	path := appApprovalsPath(home)
	if err := pathpreflight.PreflightFile(path, "app approvals", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return nil, err
	}
	data, err := readFileBounded(path, maxManifestBytes)
	if errors.Is(err, os.ErrNotExist) {
		return &appApprovalCatalog{Version: 1, Apps: map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var catalog appApprovalCatalog
	if err := appmanifest.DecodeSingleJSONStrict(data, &catalog); err != nil {
		return nil, fmt.Errorf("app_approval_invalid: %w", err)
	}
	if catalog.Version != 1 || catalog.Apps == nil {
		return nil, fmt.Errorf("app_approval_invalid: unsupported catalog")
	}
	for name, origin := range catalog.Apps {
		normalized, err := normalizePluginName(name)
		if err != nil || normalized != name {
			return nil, fmt.Errorf("app_approval_invalid: invalid app id")
		}
		canonical, err := canonicalAppOrigin(origin)
		if err != nil || canonical != origin {
			return nil, fmt.Errorf("app_approval_invalid: invalid origin for %s", name)
		}
	}
	return &catalog, nil
}

func changeAppApproval(home, name, origin string) error {
	lockPath := appApprovalsPath(home) + ".lock"
	if err := pathpreflight.PreflightFile(lockPath, "app approval lock", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return err
	}
	lock, err := awconfig.LockExclusive(lockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	catalog, err := loadAppApprovals(home)
	if err != nil {
		return err
	}
	if origin == "" {
		delete(catalog.Apps, name)
	} else {
		catalog.Apps[name] = origin
	}
	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(home, ".app-approvals-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), appApprovalsPath(home))
}

// No selected-home failure is retried against the instance directory. A plain
// shell without an identity retains the released host-only install behavior.
func pluginManagementHome() (awconfig.IdentityHome, bool, error) {
	home, err := identityHomeForDir(mustGetwd())
	if err != nil {
		return home, false, err
	}
	if _, err := os.Lstat(awconfig.GrantHomeStatePath(home.Root)); err == nil {
		return home, false, usageError("app_management_denied: grant homes cannot install, update or remove apps; use the resident home")
	} else if !errors.Is(err, os.ErrNotExist) {
		return home, false, err
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(home.Root, "identity.yaml"))
	if errors.Is(err, os.ErrNotExist) && !home.External() {
		return home, false, nil
	}
	if err != nil {
		return home, false, fmt.Errorf("app_resident_required: %w", err)
	}
	if identity == nil || strings.TrimSpace(identity.DID) == "" {
		return home, false, usageError("app_resident_required: selected home has no resident identity")
	}
	return home, true, nil
}

// Apps is emitted from the snapshots actually committed for this grant, never
// from a worker's store or from a requested/configured app list.
type grantAppInventoryItem struct {
	AppID          string   `json:"app_id"`
	Origin         string   `json:"origin"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	Tools          []string `json:"tools"`
}

func grantAppInventory(apps map[string]grantAppSnapshot) []grantAppInventoryItem {
	out := make([]grantAppInventoryItem, 0, len(apps))
	for name, app := range apps {
		item := grantAppInventoryItem{AppID: name, Origin: app.App.Origin, ManifestSHA256: app.ManifestSHA256, Tools: []string{}}
		for _, tool := range app.Tools {
			item.Tools = append(item.Tools, tool.Name)
		}
		sort.Strings(item.Tools)
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AppID < out[j].AppID })
	return out
}

type skippedGrantApp struct {
	AppID string `json:"app_id"`
	Code  string `json:"code"`
}

func selectGrantAppSnapshots(home string, explicit bool, values, deniedOrigins []string) (map[string]grantAppSnapshot, error) {
	apps, _, err := prepareGrantAppSnapshots(home, explicit, values, deniedOrigins)
	return apps, err
}

// Catalog failures narrow this mint's authority without preventing unrelated
// communication. Explicit legacy selections and corrupt resident state fail.
func prepareGrantAppSnapshots(home string, explicit bool, values, deniedOrigins []string) (map[string]grantAppSnapshot, []skippedGrantApp, error) {
	skipped := []skippedGrantApp{}
	if explicit {
		specs, err := parseGrantAppToolSpecs(values)
		if err != nil {
			return nil, nil, err
		}
		if len(specs) == 0 {
			return nil, nil, usageError("--app-tool requires a nonempty app:verb selection")
		}
		apps, err := buildGrantAppSnapshots(specs, deniedOrigins)
		return apps, skipped, err
	}
	catalog, err := loadAppApprovals(home)
	if err != nil {
		return nil, nil, err
	}
	apps := map[string]grantAppSnapshot{}
	names := make([]string, 0, len(catalog.Apps))
	for name := range catalog.Apps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		selected, err := buildGrantAppSnapshotsWithApprovals(map[string][]string{name: nil}, deniedOrigins, catalog.Apps)
		if err != nil {
			code := "app_manifest_invalid"
			var failure *appSnapshotFailure
			if errors.As(err, &failure) {
				code = failure.code
			}
			skipped = append(skipped, skippedGrantApp{AppID: name, Code: code})
			continue
		}
		apps[name] = selected[name]
	}
	return apps, skipped, nil
}
