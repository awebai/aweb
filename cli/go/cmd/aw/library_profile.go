package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/awebai/aw/internal/profilepack"
)

type libraryProfileSelector struct {
	SourceProfilePackRef     string
	SourceProfilePackVersion string
	ProfileRef               string
}

type libraryProfileDetailResponse struct {
	PackRef            string                                  `json:"pack_ref"`
	PackVersion        string                                  `json:"pack_version"`
	ProfileRef         string                                  `json:"profile_ref"`
	Version            string                                  `json:"version"`
	Digest             string                                  `json:"digest"`
	RuntimeAssumptions []string                                `json:"runtime_assumptions"`
	Files              []profilepack.LibraryProfilePayloadFile `json:"files"`
}

type libraryImportToShelfResponse struct {
	ProfileRef               string `json:"profile_ref"`
	Version                  string `json:"version"`
	Digest                   string `json:"digest"`
	SourceProfilePackRef     string `json:"source_profile_pack_ref"`
	SourceProfilePackVersion string `json:"source_profile_pack_version"`
	SourceProfilePackDigest  string `json:"source_profile_pack_digest"`
	Created                  bool   `json:"created"`
}

func parseLibraryProfileSelector(raw string) (libraryProfileSelector, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return libraryProfileSelector{}, usageError("profile selector is required")
	}
	packAndProfile := trimmed
	version := ""
	if before, after, ok := strings.Cut(trimmed, "@"); ok {
		packAndProfile = strings.TrimSpace(before)
		version = strings.TrimSpace(after)
		if version == "" {
			return libraryProfileSelector{}, usageError("profile pack version is required after @")
		}
	}
	packRef, profileRef, ok := strings.Cut(packAndProfile, "/")
	if !ok {
		return libraryProfileSelector{}, usageError("profile selector %q must be PACK_REF/PROFILE_REF[@PACK_VERSION]", raw)
	}
	selector := libraryProfileSelector{SourceProfilePackRef: strings.TrimSpace(packRef), SourceProfilePackVersion: version, ProfileRef: strings.TrimSpace(profileRef)}
	if err := validateLibraryRef("source profile pack ref", selector.SourceProfilePackRef, false); err != nil {
		return libraryProfileSelector{}, err
	}
	if err := validateLibraryRef("profile ref", selector.ProfileRef, false); err != nil {
		return libraryProfileSelector{}, err
	}
	if selector.SourceProfilePackVersion != "" {
		if err := validateLibraryRef("source profile pack version", selector.SourceProfilePackVersion, true); err != nil {
			return libraryProfileSelector{}, err
		}
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

func applyLibraryProfileToHome(homeDir, agentID string, selector libraryProfileSelector, force bool) (*profilepack.MaterializeResult, []string, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, nil, fmt.Errorf("agent id is required for Library binding")
	}
	var materialized *profilepack.MaterializeResult
	var written []string
	err := withWorkingDir(homeDir, func() error {
		profile, err := callLibraryGetProfile(selector)
		if err != nil {
			return fmt.Errorf("library get-profile: %w", err)
		}
		runtimeKind := chooseLibraryRuntimeKind(profile.RuntimeAssumptions)
		imported, err := callLibraryImportToShelf(selector)
		if err != nil {
			return fmt.Errorf("library import-to-shelf: %w", err)
		}
		if err := validateFetchedProfileMatchesImport(selector, profile, imported); err != nil {
			return err
		}
		if err := callLibraryBind(strings.TrimSpace(agentID), imported); err != nil {
			return fmt.Errorf("library bind: %w", err)
		}
		materialized, err = profilepack.MaterializeLibraryProfilePayload(profilepack.MaterializeLibraryProfilePayloadOptions{
			TargetDir:      homeDir,
			PackRef:        imported.SourceProfilePackRef,
			PackVersion:    firstNonEmptyLibraryValue(imported.SourceProfilePackVersion, profile.PackVersion, selector.SourceProfilePackVersion),
			PackDigest:     imported.SourceProfilePackDigest,
			ProfileRef:     imported.ProfileRef,
			ProfileVersion: firstNonEmptyLibraryValue(imported.Version, profile.Version),
			ProfileDigest:  firstNonEmptyLibraryValue(imported.Digest, profile.Digest),
			RuntimeKind:    runtimeKind,
			Files:          profile.Files,
			Force:          force,
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
	body, err := executeLibraryToolBody([]string{"get-profile", "--pack_ref", selector.SourceProfilePackRef, "--profile_ref", selector.ProfileRef})
	if err != nil {
		return nil, err
	}
	var out libraryProfileDetailResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode library get-profile response: %w", err)
	}
	if out.ProfileRef == "" {
		out.ProfileRef = selector.ProfileRef
	}
	if out.PackRef == "" {
		out.PackRef = selector.SourceProfilePackRef
	}
	if out.PackVersion == "" {
		out.PackVersion = selector.SourceProfilePackVersion
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
		{field: "pack_ref", got: profile.PackRef, want: imported.SourceProfilePackRef},
		{field: "profile_ref", got: profile.ProfileRef, want: imported.ProfileRef},
		{field: "profile_version", got: profile.Version, want: imported.Version},
		{field: "profile_digest", got: profile.Digest, want: imported.Digest},
	}
	if strings.TrimSpace(imported.SourceProfilePackVersion) != "" {
		checks = append(checks, struct {
			field string
			got   string
			want  string
		}{field: "pack_version", got: profile.PackVersion, want: imported.SourceProfilePackVersion})
	}
	if strings.TrimSpace(selector.SourceProfilePackVersion) != "" {
		checks = append(checks, struct {
			field string
			got   string
			want  string
		}{field: "selector_pack_version", got: profile.PackVersion, want: selector.SourceProfilePackVersion})
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

func chooseLibraryRuntimeKind(assumptions []string) string {
	allowed := map[string]bool{}
	for _, assumption := range assumptions {
		allowed[strings.ToLower(strings.TrimSpace(assumption))] = true
	}
	switch {
	case allowed["claude-code"]:
		return "claude-code"
	case allowed["codex"]:
		return "codex"
	case allowed["pi"]:
		return "pi"
	case allowed["local shell"] || allowed["local-shell"]:
		return "local-shell"
	default:
		return "claude-code"
	}
}

func callLibraryImportToShelf(selector libraryProfileSelector) (*libraryImportToShelfResponse, error) {
	args := []string{"import-to-shelf", "--source_profile_pack_ref", selector.SourceProfilePackRef, "--profile_ref", selector.ProfileRef}
	if strings.TrimSpace(selector.SourceProfilePackVersion) != "" {
		args = append(args, "--source_profile_pack_version", selector.SourceProfilePackVersion)
	}
	body, err := executeLibraryToolBody(args)
	if err != nil {
		return nil, err
	}
	var out libraryImportToShelfResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode library import-to-shelf response: %w", err)
	}
	if out.ProfileRef == "" || out.Version == "" || out.Digest == "" {
		return nil, fmt.Errorf("library import-to-shelf response missing profile ref/version/digest")
	}
	if out.SourceProfilePackRef == "" {
		out.SourceProfilePackRef = selector.SourceProfilePackRef
	}
	return &out, nil
}

func callLibraryBind(agentID string, imported *libraryImportToShelfResponse) error {
	if imported == nil {
		return fmt.Errorf("library import result is required")
	}
	_, err := executeLibraryToolBody([]string{
		"bind",
		"--agent_id", agentID,
		"--profile_ref", imported.ProfileRef,
		"--profile_version", imported.Version,
		"--profile_digest", imported.Digest,
		"--source_profile_pack_ref", imported.SourceProfilePackRef,
	})
	return err
}

func executeLibraryToolBody(args []string) ([]byte, error) {
	result, exists, err := executeInstalledManifestTool("library", args)
	if !exists {
		return nil, usageError("aw library plugin is not installed; run `aw plugin install https://library.aweb.ai/.well-known/aweb-app.json`")
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
