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
// team/installation bindings supply the default authority for a newly minted grant.
// Origin-only consent is retained for diagnostics and never adopted as authority.
type appInstallationApproval struct {
	Origin         string `json:"origin"`
	InstallationID string `json:"installation_id"`
}

type appApprovalCatalog struct {
	Version       int                                           `json:"version"`
	Apps          map[string]string                             `json:"apps"`
	Installations map[string]map[string]appInstallationApproval `json:"installations"`
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
	for team, apps := range catalog.Installations {
		if strings.TrimSpace(team) == "" {
			return nil, fmt.Errorf("app_approval_invalid: missing team")
		}
		for name, approval := range apps {
			normalized, err := normalizePluginName(name)
			origin, originErr := canonicalAppOrigin(approval.Origin)
			if err != nil || normalized != name || originErr != nil || origin != approval.Origin || strings.TrimSpace(approval.InstallationID) == "" {
				return nil, fmt.Errorf("app_approval_invalid: invalid installation binding")
			}
		}
	}
	return &catalog, nil
}

func changeAppApproval(home, name, origin, teamID, installationID string) error {
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
	if catalog.Installations == nil {
		catalog.Installations = map[string]map[string]appInstallationApproval{}
	}
	if origin == "" {
		delete(catalog.Apps, name)
		for _, apps := range catalog.Installations {
			delete(apps, name)
		}
	} else {
		if strings.TrimSpace(teamID) == "" || strings.TrimSpace(installationID) == "" {
			return fmt.Errorf("app_installation_approval_required: explicit install requires a team installation identity")
		}
		catalog.Apps[name] = origin
		if catalog.Installations[teamID] == nil {
			catalog.Installations[teamID] = map[string]appInstallationApproval{}
		}
		catalog.Installations[teamID][name] = appInstallationApproval{Origin: origin, InstallationID: installationID}
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
		return home, false, usageError("app_management_denied: grant homes cannot install, update or remove apps. Ask the resident owner to repeat this command with --identity-home <resident-credential-directory>: the directory containing signing.key and identity.yaml or teams.yaml, normally <resident-root>/.aw (not its parent). Keep the same resident identity; do not copy keys into the grant home")
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
	AppID           string   `json:"app_id"`
	Code            string   `json:"code"`
	Origin          string   `json:"origin,omitempty"`
	RecoveryCommand []string `json:"recovery_command,omitempty"`
}

func selectGrantAppSnapshots(home, teamID string, explicit bool, values, deniedOrigins []string) (map[string]grantAppSnapshot, error) {
	apps, _, err := prepareGrantAppSnapshots(home, teamID, explicit, values, deniedOrigins)
	return apps, err
}

// Catalog failures narrow this mint's authority without preventing unrelated
// communication. Explicit legacy selections and corrupt resident state fail.
func prepareGrantAppSnapshots(home, teamID string, explicit bool, values, deniedOrigins []string) (map[string]grantAppSnapshot, []skippedGrantApp, error) {
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
		if err != nil {
			return nil, nil, err
		}
		catalog, err := loadAppApprovals(home)
		if err != nil {
			return nil, nil, err
		}
		for name, app := range apps {
			approval := catalog.Installations[teamID][name]
			if approval.InstallationID == "" {
				return nil, nil, installationApprovalError("app_installation_approval_required", app.App.Origin, home, teamID)
			}
			if approval.Origin != app.App.Origin {
				return nil, nil, installationApprovalError("app_origin_mismatch", app.App.Origin, home, teamID)
			}
			app.InstallationID = approval.InstallationID
			apps[name] = app
		}
		return apps, skipped, nil
	}
	catalog, err := loadAppApprovals(home)
	if err != nil {
		return nil, nil, err
	}
	approvals := map[string]string{}
	for name, approval := range catalog.Installations[teamID] {
		approvals[name] = approval.Origin
	}
	apps := map[string]grantAppSnapshot{}
	names := make([]string, 0, len(catalog.Apps))
	for name := range catalog.Apps {
		names = append(names, name)
	}
	for name := range approvals {
		if _, ok := catalog.Apps[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		approval, bound := catalog.Installations[teamID][name]
		if !bound {
			skipped = append(skipped, skippedGrantApp{AppID: name, Code: "app_installation_approval_required", Origin: catalog.Apps[name]})
			continue
		}
		selected, err := buildGrantAppSnapshotsWithApprovals(map[string][]string{name: nil}, deniedOrigins, approvals)
		if err != nil {
			code := "app_manifest_invalid"
			var failure *appSnapshotFailure
			if errors.As(err, &failure) {
				code = failure.code
			}
			skipped = append(skipped, skippedGrantApp{AppID: name, Code: code})
			continue
		}
		snapshot := selected[name]
		snapshot.InstallationID = approval.InstallationID
		apps[name] = snapshot
	}
	return apps, skipped, nil
}
