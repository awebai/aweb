package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	defaultLibraryBaseURL         = "https://library.aweb.ai"
	defaultLibraryBlueprintRef    = "aweb.team"
	libraryURLEnvVar              = "AWEB_LIBRARY_URL"
	libraryBlueprintEnvVar        = "AWEB_BLUEPRINT"
	libraryPluginName             = "library"
	libraryPluginManifestURL      = defaultLibraryBaseURL + "/.well-known/aweb-app.json"
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
	LibraryURL             string
	SourceBlueprintRef     string
	SourceBlueprintVersion string
	ProfileRef             string
	RuntimeKind            string
	IdentityScope          string
	PublicProfile          *libraryProfileDetailResponse
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

type libraryMaterializeResponse struct {
	ProfileRef             string                      `json:"profile_ref"`
	ProfileVersion         string                      `json:"profile_version"`
	ProfileDigest          string                      `json:"profile_digest"`
	SourceBlueprintRef     string                      `json:"source_blueprint_ref"`
	SourceBlueprintVersion string                      `json:"source_blueprint_version"`
	SourceBlueprintDigest  string                      `json:"source_blueprint_digest"`
	HomeFiles              []blueprint.LibraryHomeFile `json:"home_files"`
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
		blueprintRef = ""
		profileRef = blueprintAndProfile
	}
	selector := libraryProfileSelector{SourceBlueprintRef: strings.TrimSpace(blueprintRef), ProfileRef: strings.TrimSpace(profileRef), RuntimeKind: runtimeKind, IdentityScope: identityScope}
	if selector.SourceBlueprintRef != "" {
		if err := validateLibraryRef("source blueprint ref", selector.SourceBlueprintRef, false); err != nil {
			return libraryProfileSelector{}, err
		}
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
	_, scope, err := resolveLibraryProfileScopeAndCache(selector)
	return scope, err
}

func resolveLibraryProfileScopeAndCache(selector libraryProfileSelector) (libraryProfileSelector, string, error) {
	if scope := strings.TrimSpace(selector.IdentityScope); scope != "" {
		normalized, err := normalizeTeamAgentScope(scope)
		return selector, normalized, err
	}
	var profile *libraryProfileDetailResponse
	var err error
	if strings.TrimSpace(selector.LibraryURL) != "" {
		profile, err = publicLibraryProfileForSelector(context.Background(), selector)
		selector.PublicProfile = profile
	} else {
		profile, err = callLibraryGetProfile(selector)
	}
	if err != nil {
		return selector, "", err
	}
	scope, err := profileScopeFromLibraryPayload(profile)
	if err != nil {
		return selector, "", err
	}
	if scope == "" {
		return selector, awid.IdentityModeLocal, nil
	}
	normalized, err := normalizeTeamAgentScope(scope)
	return selector, normalized, err
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

func applyPublicLibraryProfileToHome(homeDir string, selector libraryProfileSelector, force bool) (*blueprint.MaterializeResult, []string, error) {
	if strings.TrimSpace(selector.LibraryURL) == "" {
		return nil, nil, fmt.Errorf("library url is required for public profile materialization")
	}
	if err := rejectUnsupportedVersionedLibrarySelector(selector); err != nil {
		return nil, nil, err
	}
	var materialized *blueprint.MaterializeResult
	err := withWorkingDir(homeDir, func() error {
		profile, err := publicLibraryProfileForSelector(context.Background(), selector)
		if err != nil {
			return fmt.Errorf("library public get-profile: %w", err)
		}
		runtimeKind, err := materializeRuntimeKindForSelector(selector)
		if err != nil {
			return err
		}
		materialized, err = blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
			TargetDir:        homeDir,
			LibraryURL:       selector.LibraryURL,
			BlueprintRef:     profile.BlueprintRef,
			BlueprintVersion: profile.BlueprintVersion,
			ProfileRef:       profile.ProfileRef,
			ProfileVersion:   profile.Version,
			ProfileDigest:    profile.Digest,
			RuntimeKind:      runtimeKind,
			Files:            profile.Files,
			Force:            force,
		})
		if err != nil {
			return fmt.Errorf("local profile materialize: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return materialized, materialized.FilesWritten, nil
}

func applyPublicLibraryProfileToHomeAndConfigure(homeDir string, selector libraryProfileSelector, force bool) (*blueprint.MaterializeResult, []string, error) {
	materialized, written, err := applyPublicLibraryProfileToHome(homeDir, selector, force)
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
		return fmt.Errorf("set up Claude Code aweb-channel plugin: %w", result.Error)
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

func resolveLibraryProfileSelectorSource(selector libraryProfileSelector, libraryURLFlag, blueprintFlag string) (libraryProfileSelector, error) {
	libraryURL, err := resolveLibraryBaseURL(libraryURLFlag)
	if err != nil {
		return libraryProfileSelector{}, err
	}
	selector.LibraryURL = libraryURL
	resolvedBlueprint := strings.TrimSpace(selector.SourceBlueprintRef)
	flagBlueprint := strings.TrimSpace(blueprintFlag)
	if resolvedBlueprint != "" {
		if flagBlueprint != "" && flagBlueprint != resolvedBlueprint {
			fmt.Fprintf(os.Stderr, "Warning: selector blueprint %s overrides --blueprint %s\n", resolvedBlueprint, flagBlueprint)
		}
	} else {
		resolvedBlueprint = firstNonEmptyLibraryValue(flagBlueprint, os.Getenv(libraryBlueprintEnvVar), defaultLibraryBlueprintRef)
		selector.SourceBlueprintRef = resolvedBlueprint
	}
	if err := validateLibraryRef("source blueprint ref", selector.SourceBlueprintRef, false); err != nil {
		return libraryProfileSelector{}, err
	}
	return selector, nil
}

func resolveLibraryBaseURL(flag string) (string, error) {
	raw := firstNonEmptyLibraryValue(flag, os.Getenv(libraryURLEnvVar), defaultLibraryBaseURL)
	return normalizeLibraryBaseURL(raw)
}

func normalizeLibraryBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", usageError("library URL is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid library URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", usageError("library URL %q must use http or https", raw)
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", usageError("library URL %q must include a host", raw)
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	return strings.TrimRight(u.String(), "/"), nil
}

func publicLibraryProfileForSelector(ctx context.Context, selector libraryProfileSelector) (*libraryProfileDetailResponse, error) {
	if selector.PublicProfile != nil {
		return selector.PublicProfile, nil
	}
	return fetchPublicLibraryProfile(ctx, selector)
}

func fetchPublicLibraryProfile(ctx context.Context, selector libraryProfileSelector) (*libraryProfileDetailResponse, error) {
	base := strings.TrimSpace(selector.LibraryURL)
	if base == "" {
		return nil, fmt.Errorf("library url is required")
	}
	endpoint, err := url.JoinPath(base, "v1", "blueprints", selector.SourceBlueprintRef, "profiles", selector.ProfileRef)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GET %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out libraryProfileDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode library get-profile response: %w", err)
	}
	if err := validateLibraryProfileDetailResponse(&out); err != nil {
		return nil, err
	}
	if out.BlueprintRef != selector.SourceBlueprintRef {
		return nil, fmt.Errorf("library get-profile response blueprint_ref %q does not match requested %q", out.BlueprintRef, selector.SourceBlueprintRef)
	}
	if out.ProfileRef != selector.ProfileRef {
		return nil, fmt.Errorf("library get-profile response profile_ref %q does not match requested %q", out.ProfileRef, selector.ProfileRef)
	}
	return &out, nil
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
	if err := validateLibraryProfileDetailResponse(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func validateLibraryProfileDetailResponse(out *libraryProfileDetailResponse) error {
	if out == nil || out.BlueprintRef == "" || out.BlueprintVersion == "" || out.ProfileRef == "" || out.Version == "" || out.Digest == "" {
		return fmt.Errorf("library get-profile response missing blueprint_ref/blueprint_version/profile_ref/version/digest")
	}
	if len(out.Files) == 0 {
		return fmt.Errorf("library get-profile response missing files")
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

func callLibraryImportToShelfWithMissingErr(selector libraryProfileSelector, missingErr error) (*libraryImportToShelfResponse, error) {
	args := []string{"import-to-shelf", "--source_blueprint_ref", selector.SourceBlueprintRef, "--profile_ref", selector.ProfileRef}
	if strings.TrimSpace(selector.SourceBlueprintVersion) != "" {
		args = append(args, "--source_blueprint_version", selector.SourceBlueprintVersion)
	}
	body, err := executeLibraryToolBody(args, missingErr)
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

func effectiveLibraryManifestMaterializeArgs(name, verb string, parsedArgs map[string]any, body []byte) (map[string]any, error) {
	if name != libraryPluginName || verb != "materialize" || len(body) == 0 {
		return parsedArgs, nil
	}
	effective := make(map[string]any, len(parsedArgs))
	for key, value := range parsedArgs {
		effective[key] = value
	}
	var bodyArgs map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&bodyArgs); err != nil {
		return nil, fmt.Errorf("decode interpreted library materialize body: %w", err)
	}
	for key, value := range bodyArgs {
		effective[key] = value
	}
	return effective, nil
}

func isLibraryManifestLocalMaterialize(name, verb string, args map[string]any) bool {
	if name != libraryPluginName || verb != "materialize" {
		return false
	}
	target, ok := args["target"].(string)
	return ok && strings.TrimSpace(target) == "local"
}

func applyLibraryManifestLocalMaterialize(name, verb string, args map[string]any, body []byte) error {
	if !isLibraryManifestLocalMaterialize(name, verb, args) {
		return nil
	}
	runtimeKind, ok := args["runtime_kind"].(string)
	if !ok || strings.TrimSpace(runtimeKind) == "" {
		return fmt.Errorf("library materialize --target local requires --runtime_kind")
	}
	var response libraryMaterializeResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("decode library materialize response: %w", err)
	}
	if err := validateLibraryMaterializeResponse(&response, runtimeKind); err != nil {
		return err
	}
	homeDir, err := os.Getwd()
	if err != nil {
		return err
	}
	old, err := readOptionalRecordedProfileRef(homeDir)
	if err != nil {
		return err
	}
	// A recorded managed set is an existing materialized home and follows refresh
	// overwrite semantics. A first materialization still rejects local collisions.
	force := len(old.ManagedSet) > 0
	written, err := blueprint.WriteLibraryHomeFiles(homeDir, response.HomeFiles, force)
	if err != nil {
		return fmt.Errorf("local Library home materialize: %w", err)
	}
	if err := pruneRemovedManagedProfileFiles(homeDir, old.ManagedSet, written); err != nil {
		return fmt.Errorf("prune removed Library home files: %w", err)
	}
	return nil
}

func validateLibraryMaterializeResponse(response *libraryMaterializeResponse, runtimeKind string) error {
	if response == nil || strings.TrimSpace(response.ProfileRef) == "" || strings.TrimSpace(response.ProfileVersion) == "" || strings.TrimSpace(response.ProfileDigest) == "" {
		return fmt.Errorf("library materialize response missing profile_ref/profile_version/profile_digest")
	}
	var refFile *blueprint.LibraryHomeFile
	for i := range response.HomeFiles {
		if filepath.ToSlash(strings.TrimSpace(response.HomeFiles[i].Path)) == ".aw/profile/ref.json" {
			if refFile != nil {
				return fmt.Errorf("library materialize response contains duplicate .aw/profile/ref.json")
			}
			refFile = &response.HomeFiles[i]
		}
	}
	if refFile == nil || strings.TrimSpace(refFile.Kind) != "file" {
		return fmt.Errorf("library materialize response missing file .aw/profile/ref.json")
	}
	var pin recordedProfileRef
	if err := json.Unmarshal([]byte(refFile.ContentUTF8), &pin); err != nil {
		return fmt.Errorf("decode materialized .aw/profile/ref.json: %w", err)
	}
	checks := []struct {
		field string
		got   string
		want  string
	}{
		{field: "profile_ref", got: pin.ProfileRef, want: response.ProfileRef},
		{field: "profile_version", got: pin.ProfileVersion, want: response.ProfileVersion},
		{field: "profile_digest", got: pin.ProfileDigest, want: response.ProfileDigest},
		{field: "runtime_kind", got: pin.RuntimeKind, want: runtimeKind},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.got) == "" || strings.TrimSpace(check.got) != strings.TrimSpace(check.want) {
			return fmt.Errorf("library materialize response %s %q does not match ref.json %q", check.field, strings.TrimSpace(check.want), strings.TrimSpace(check.got))
		}
	}
	if len(pin.ManagedSet) != len(response.HomeFiles) {
		return fmt.Errorf("materialized ref.json managed_set has %d paths for %d home_files", len(pin.ManagedSet), len(response.HomeFiles))
	}
	for i, file := range response.HomeFiles {
		rel := filepath.ToSlash(strings.TrimSpace(file.Path))
		if pin.ManagedSet[i] != rel {
			return fmt.Errorf("materialized ref.json managed_set path %d is %q, want %q", i, pin.ManagedSet[i], rel)
		}
	}
	return nil
}

func readOptionalRecordedProfileRef(homeDir string) (recordedProfileRef, error) {
	var ref recordedProfileRef
	refPath := filepath.Join(homeDir, ".aw", "profile", "ref.json")
	data, err := os.ReadFile(refPath)
	if os.IsNotExist(err) {
		return ref, nil
	}
	if err != nil {
		return ref, fmt.Errorf("read %s: %w", refPath, err)
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		return ref, fmt.Errorf("parse %s: %w", refPath, err)
	}
	return ref, nil
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
