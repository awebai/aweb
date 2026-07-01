package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/blueprint"
	"gopkg.in/yaml.v3"
)

const (
	defaultMaterializeRuntimeKind = "claude-code"
	libraryPluginName             = "library"
	libraryPluginManifestURL      = "https://library.aweb.ai/.well-known/aweb-app.json"
	libraryPluginInstallCommand   = "aw plugin install " + libraryPluginManifestURL
)

const missingLibraryPluginMarker = "Library plugin"

func missingLibraryPluginCommandError() error {
	return usageError("The aw Library plugin is not installed. Install it with:\n    %s", libraryPluginInstallCommand)
}

func missingLibraryPluginProfileError(selector libraryProfileSelector) error {
	return usageError("Adding an agent from a Library profile (%s) requires the aw Library plugin, which is not installed. Install it, then re-run:\n    %s", libraryProfileSelectorLabel(selector), libraryPluginInstallCommand)
}

func isMissingLibraryPluginError(err error) bool {
	return err != nil && strings.Contains(err.Error(), missingLibraryPluginMarker) && strings.Contains(err.Error(), "not installed")
}

func libraryProfileSelectorLabel(selector libraryProfileSelector) string {
	blueprintRef := strings.TrimSpace(selector.SourceBlueprintRef)
	profileRef := strings.TrimSpace(selector.ProfileRef)
	if blueprintRef == "" || profileRef == "" {
		return "NAME@BLUEPRINT/PROFILE"
	}
	return blueprintRef + "/" + profileRef
}

type libraryProfileSelector struct {
	SourceBlueprintRef     string
	SourceBlueprintVersion string
	ProfileRef             string
	RuntimeKind            string
	IdentityScope          string
}

type libraryProfileDetailResponse struct {
	BlueprintRef       string                                `json:"blueprint_ref"`
	BlueprintVersion   string                                `json:"blueprint_version"`
	ProfileRef         string                                `json:"profile_ref"`
	Version            string                                `json:"version"`
	Digest             string                                `json:"digest"`
	RuntimeAssumptions []string                              `json:"runtime_assumptions"`
	RuntimeHints       []string                              `json:"runtime_hints"`
	Files              []blueprint.LibraryProfilePayloadFile `json:"files"`
}

type libraryImportToShelfResponse struct {
	ProfileRef             string `json:"profile_ref"`
	Version                string `json:"version"`
	Digest                 string `json:"digest"`
	SourceBlueprintRef     string `json:"source_blueprint_ref"`
	SourceBlueprintVersion string `json:"source_blueprint_version"`
	SourceBlueprintDigest  string `json:"source_blueprint_digest"`
	Created                bool   `json:"created"`
}

type libraryBindResponse struct {
	AgentID        string `json:"agent_id"`
	ProfileRef     string `json:"profile_ref"`
	ProfileVersion string `json:"profile_version"`
	ProfileDigest  string `json:"profile_digest"`
}

func parseLibraryProfileSelector(raw string) (libraryProfileSelector, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return libraryProfileSelector{}, usageError("profile selector is required")
	}
	runtimeKind := ""
	blueprintProfileScope := trimmed
	if before, after, ok := strings.Cut(trimmed, "="); ok {
		blueprintProfileScope = strings.TrimSpace(before)
		runtimeKind = strings.TrimSpace(after)
		if runtimeKind == "" {
			return libraryProfileSelector{}, usageError("runtime is required after =")
		}
		var err error
		runtimeKind, err = normalizeMaterializeRuntimeKind(runtimeKind)
		if err != nil {
			return libraryProfileSelector{}, err
		}
	}
	if strings.Contains(blueprintProfileScope, "@") {
		return libraryProfileSelector{}, usageError("versioned Library profile selectors are not supported; @ now separates NAME from BLUEPRINT/PROFILE, use [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]")
	}
	identityScope := ""
	blueprintAndProfile := blueprintProfileScope
	if before, after, ok := strings.Cut(blueprintProfileScope, ":"); ok {
		blueprintAndProfile = strings.TrimSpace(before)
		var err error
		identityScope, err = normalizeTeamAgentScope(after)
		if err != nil {
			return libraryProfileSelector{}, err
		}
	}
	blueprintRef, profileRef, ok := strings.Cut(blueprintAndProfile, "/")
	if !ok {
		return libraryProfileSelector{}, usageError("profile selector %q must be BLUEPRINT_REF/PROFILE_REF[:local|global][=RUNTIME]", raw)
	}
	selector := libraryProfileSelector{SourceBlueprintRef: strings.TrimSpace(blueprintRef), ProfileRef: strings.TrimSpace(profileRef), RuntimeKind: runtimeKind, IdentityScope: identityScope}
	if err := validateLibraryRef("source blueprint ref", selector.SourceBlueprintRef, false); err != nil {
		return libraryProfileSelector{}, err
	}
	if err := validateLibraryRef("profile ref", selector.ProfileRef, false); err != nil {
		return libraryProfileSelector{}, err
	}
	return selector, nil
}

func normalizeTeamAgentScope(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", usageError("scope is required after :")
	case awid.IdentityModeLocal:
		return awid.IdentityModeLocal, nil
	case awid.IdentityModeGlobal:
		return awid.IdentityModeGlobal, nil
	default:
		return "", usageError("scope %q is not supported; use local or global", raw)
	}
}

func resolveLibraryProfileScope(selector libraryProfileSelector) (string, error) {
	if scope := strings.TrimSpace(selector.IdentityScope); scope != "" {
		return normalizeTeamAgentScope(scope)
	}
	profile, err := callLibraryGetProfile(selector)
	if err != nil {
		return "", err
	}
	scope, err := profileScopeFromLibraryPayload(profile)
	if err != nil {
		return "", err
	}
	if scope == "" {
		return awid.IdentityModeLocal, nil
	}
	return normalizeTeamAgentScope(scope)
}

func profileScopeFromLibraryPayload(profile *libraryProfileDetailResponse) (string, error) {
	if profile == nil {
		return "", fmt.Errorf("library profile is required")
	}
	for _, file := range profile.Files {
		if filepath.ToSlash(strings.TrimSpace(file.Path)) != "profile.yaml" {
			continue
		}
		var doc struct {
			Scope string `yaml:"scope"`
		}
		if err := yaml.Unmarshal([]byte(file.ContentUTF8), &doc); err != nil {
			return "", fmt.Errorf("library profile %s/profile.yaml: parse scope: %w", profile.ProfileRef, err)
		}
		return strings.TrimSpace(doc.Scope), nil
	}
	return "", nil
}

func rejectUnsupportedVersionedLibrarySelector(selector libraryProfileSelector) error {
	if strings.TrimSpace(selector.SourceBlueprintVersion) != "" {
		return usageError("versioned Library profile selectors are not supported until get-profile exposes versioned source; omit @%s", selector.SourceBlueprintVersion)
	}
	return nil
}

func applyMaterializeRuntimePolicy(selector libraryProfileSelector, runtimeFlag string) (libraryProfileSelector, error) {
	flagRuntime := strings.TrimSpace(runtimeFlag)
	if flagRuntime != "" {
		normalized, err := normalizeMaterializeRuntimeKind(flagRuntime)
		if err != nil {
			return libraryProfileSelector{}, err
		}
		if strings.TrimSpace(selector.RuntimeKind) == "" {
			selector.RuntimeKind = normalized
		}
	}
	if strings.TrimSpace(selector.RuntimeKind) == "" {
		selector.RuntimeKind = defaultMaterializeRuntimeKind
	}
	return selector, nil
}

func validateLibraryRef(field, value string, allowSlash bool) error {
	if strings.TrimSpace(value) == "" {
		return usageError("%s is required", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return usageError("%s contains control characters", field)
		}
	}
	if strings.Contains(value, "://") || strings.HasPrefix(value, "git@") || filepath.IsAbs(value) {
		return usageError("%s must be a Library ref, not a URL or path", field)
	}
	if strings.Contains(value, "..") || (!allowSlash && strings.Contains(value, "/")) {
		return usageError("%s contains invalid path components", field)
	}
	return nil
}

func applyLibraryProfileToHome(homeDir, agentID string, selector libraryProfileSelector, force bool) (*blueprint.MaterializeResult, []string, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, nil, fmt.Errorf("agent id is required for Library binding")
	}
	if err := rejectUnsupportedVersionedLibrarySelector(selector); err != nil {
		return nil, nil, err
	}
	var materialized *blueprint.MaterializeResult
	var written []string
	err := withWorkingDir(homeDir, func() error {
		profile, err := callLibraryGetProfile(selector)
		if err != nil {
			return fmt.Errorf("library get-profile: %w", err)
		}
		runtimeKind, err := materializeRuntimeKindForSelector(selector)
		if err != nil {
			return err
		}
		imported, err := callLibraryImportToShelf(selector)
		if err != nil {
			return fmt.Errorf("library import-to-shelf: %w", err)
		}
		if err := validateFetchedProfileMatchesImport(selector, profile, imported); err != nil {
			return err
		}
		bound, err := callLibraryBind(strings.TrimSpace(agentID), imported)
		if err != nil {
			return fmt.Errorf("library bind: %w", err)
		}
		if err := validateBindMatchesImport(bound, imported); err != nil {
			return err
		}
		materialized, err = blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
			TargetDir:        homeDir,
			BlueprintRef:     imported.SourceBlueprintRef,
			BlueprintVersion: firstNonEmptyLibraryValue(imported.SourceBlueprintVersion, profile.BlueprintVersion, selector.SourceBlueprintVersion),
			BlueprintDigest:  imported.SourceBlueprintDigest,
			ProfileRef:       imported.ProfileRef,
			ProfileVersion:   firstNonEmptyLibraryValue(imported.Version, profile.Version),
			ProfileDigest:    firstNonEmptyLibraryValue(imported.Digest, profile.Digest),
			RuntimeKind:      runtimeKind,
			Files:            profile.Files,
			Force:            force,
		})
		if err != nil {
			return fmt.Errorf("local profile materialize: %w", err)
		}
		written = materialized.FilesWritten
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return materialized, written, nil
}

func applyLibraryProfileToHomeAndConfigure(homeDir, agentID string, selector libraryProfileSelector, force bool) (*blueprint.MaterializeResult, []string, error) {
	materialized, written, err := applyLibraryProfileToHome(homeDir, agentID, selector, force)
	if err != nil {
		return nil, nil, err
	}
	if err := configureMaterializedAgentHome(homeDir); err != nil {
		return nil, nil, err
	}
	return materialized, written, nil
}

func applyLocalBlueprintProfileToHome(homeDir string, selector libraryProfileSelector, sourceDir string, force bool) (*blueprint.MaterializeResult, []string, error) {
	if strings.TrimSpace(sourceDir) == "" {
		return nil, nil, fmt.Errorf("local blueprint source is required")
	}
	runtimeKind, err := materializeRuntimeKindForSelector(selector)
	if err != nil {
		return nil, nil, err
	}
	materialized, err := blueprint.MaterializeLocalProfile(blueprint.MaterializeOptions{
		SourceDir:   sourceDir,
		ProfileID:   selector.ProfileRef,
		TargetDir:   homeDir,
		RuntimeKind: runtimeKind,
		Force:       force,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("local profile materialize: %w", err)
	}
	return materialized, materialized.FilesWritten, nil
}

func configureMaterializedAgentHome(homeDir string) error {
	if result := InjectAgentDocs(homeDir); result != nil && len(result.Errors) > 0 {
		return fmt.Errorf("inject aw coordination docs: %s", strings.Join(result.Errors, "; "))
	}
	if result := SetupChannelMCP(homeDir, false); result != nil && result.Error != nil {
		return fmt.Errorf("set up channel MCP: %w", result.Error)
	}
	if result := SetupClaudeHooks(homeDir, false); result != nil && result.Error != nil {
		return fmt.Errorf("set up Claude hooks: %w", result.Error)
	}
	return nil
}

func withWorkingDir(dir string, fn func() error) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := os.Chdir(dir); err != nil {
		return err
	}
	defer func() { _ = os.Chdir(cwd) }()
	return fn()
}

func callLibraryGetProfile(selector libraryProfileSelector) (*libraryProfileDetailResponse, error) {
	body, err := executeLibraryToolBody([]string{"get-profile", "--blueprint_ref", selector.SourceBlueprintRef, "--profile_ref", selector.ProfileRef}, missingLibraryPluginProfileError(selector))
	if err != nil {
		return nil, err
	}
	var out libraryProfileDetailResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode library get-profile response: %w", err)
	}
	if out.BlueprintRef == "" || out.BlueprintVersion == "" || out.ProfileRef == "" || out.Version == "" || out.Digest == "" {
		return nil, fmt.Errorf("library get-profile response missing blueprint_ref/blueprint_version/profile_ref/version/digest")
	}
	return &out, nil
}

func validateFetchedProfileMatchesImport(selector libraryProfileSelector, profile *libraryProfileDetailResponse, imported *libraryImportToShelfResponse) error {
	if profile == nil || imported == nil {
		return fmt.Errorf("library profile source and import result are required")
	}
	checks := []struct {
		field string
		got   string
		want  string
	}{
		{field: "blueprint_ref", got: profile.BlueprintRef, want: imported.SourceBlueprintRef},
		{field: "profile_ref", got: profile.ProfileRef, want: imported.ProfileRef},
		{field: "profile_version", got: profile.Version, want: imported.Version},
		{field: "profile_digest", got: profile.Digest, want: imported.Digest},
	}
	if strings.TrimSpace(imported.SourceBlueprintVersion) != "" {
		checks = append(checks, struct {
			field string
			got   string
			want  string
		}{field: "blueprint_version", got: profile.BlueprintVersion, want: imported.SourceBlueprintVersion})
	}
	if strings.TrimSpace(selector.SourceBlueprintVersion) != "" {
		checks = append(checks, struct {
			field string
			got   string
			want  string
		}{field: "selector_blueprint_version", got: profile.BlueprintVersion, want: selector.SourceBlueprintVersion})
	}
	for _, check := range checks {
		got := strings.TrimSpace(check.got)
		want := strings.TrimSpace(check.want)
		if got == "" || want == "" || got != want {
			return fmt.Errorf("library get-profile/import mismatch for %s: fetched %q, imported %q", check.field, got, want)
		}
	}
	return nil
}

func validateBindMatchesImport(bound *libraryBindResponse, imported *libraryImportToShelfResponse) error {
	if bound == nil || imported == nil {
		return fmt.Errorf("library bind result and import result are required")
	}
	checks := []struct {
		field string
		got   string
		want  string
	}{
		{field: "profile_ref", got: bound.ProfileRef, want: imported.ProfileRef},
		{field: "profile_version", got: bound.ProfileVersion, want: imported.Version},
		{field: "profile_digest", got: bound.ProfileDigest, want: imported.Digest},
	}
	for _, check := range checks {
		got := strings.TrimSpace(check.got)
		want := strings.TrimSpace(check.want)
		if got == "" || want == "" || got != want {
			return fmt.Errorf("library bind/import mismatch for %s: bound %q, imported %q", check.field, got, want)
		}
	}
	return nil
}

func materializeRuntimeKindForSelector(selector libraryProfileSelector) (string, error) {
	if strings.TrimSpace(selector.RuntimeKind) == "" {
		return defaultMaterializeRuntimeKind, nil
	}
	return normalizeMaterializeRuntimeKind(selector.RuntimeKind)
}

func normalizeMaterializeRuntimeKind(runtimeKind string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(runtimeKind)) {
	case "claude-code":
		return "claude-code", nil
	case "codex":
		return "codex", nil
	case "pi":
		return "pi", nil
	case "local-shell", "local shell":
		return "local-shell", nil
	default:
		return "", usageError("runtime %q is not supported for materialization; supported runtimes: claude-code|codex|pi|local-shell", runtimeKind)
	}
}

func callLibraryImportToShelf(selector libraryProfileSelector) (*libraryImportToShelfResponse, error) {
	args := []string{"import-to-shelf", "--source_blueprint_ref", selector.SourceBlueprintRef, "--profile_ref", selector.ProfileRef}
	if strings.TrimSpace(selector.SourceBlueprintVersion) != "" {
		args = append(args, "--source_blueprint_version", selector.SourceBlueprintVersion)
	}
	body, err := executeLibraryToolBody(args, missingLibraryPluginProfileError(selector))
	if err != nil {
		return nil, err
	}
	var out libraryImportToShelfResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode library import-to-shelf response: %w", err)
	}
	if out.ProfileRef == "" || out.Version == "" || out.Digest == "" {
		return nil, fmt.Errorf("library import-to-shelf response missing profile_ref/version/digest")
	}
	if out.SourceBlueprintRef == "" || out.SourceBlueprintVersion == "" || out.SourceBlueprintDigest == "" {
		return nil, fmt.Errorf("library import-to-shelf response missing source_blueprint_ref/source_blueprint_version/source_blueprint_digest")
	}
	return &out, nil
}

func callLibraryBind(agentID string, imported *libraryImportToShelfResponse) (*libraryBindResponse, error) {
	if imported == nil {
		return nil, fmt.Errorf("library import result is required")
	}
	body, err := executeLibraryToolBody([]string{
		"bind",
		"--agent_id", agentID,
		"--profile_ref", imported.ProfileRef,
		"--profile_version", imported.Version,
		"--profile_digest", imported.Digest,
		"--source_blueprint_ref", imported.SourceBlueprintRef,
	}, missingLibraryPluginProfileError(libraryProfileSelector{SourceBlueprintRef: imported.SourceBlueprintRef, ProfileRef: imported.ProfileRef}))
	if err != nil {
		return nil, err
	}
	var out libraryBindResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode library bind response: %w", err)
	}
	return &out, nil
}

func executeLibraryToolBody(args []string, missingErr error) ([]byte, error) {
	result, exists, err := executeInstalledManifestTool(libraryPluginName, args)
	if !exists {
		if missingErr != nil {
			return nil, missingErr
		}
		return nil, missingLibraryPluginCommandError()
	}
	if err != nil {
		return nil, err
	}
	if result.Status >= 400 {
		return nil, fmt.Errorf("aw library %s failed with status %d: %s", args[0], result.Status, strings.TrimSpace(string(result.Body)))
	}
	return result.Body, nil
}

func firstNonEmptyLibraryValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
