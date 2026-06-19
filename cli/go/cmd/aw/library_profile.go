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

type libraryImportToShelfResponse struct {
	ProfileRef               string `json:"profile_ref"`
	Version                  string `json:"version"`
	Digest                   string `json:"digest"`
	SourceProfilePackRef     string `json:"source_profile_pack_ref"`
	SourceProfilePackVersion string `json:"source_profile_pack_version"`
	SourceProfilePackDigest  string `json:"source_profile_pack_digest"`
	Created                  bool   `json:"created"`
}

type libraryMaterializeResponse struct {
	ProfileRef               string                        `json:"profile_ref"`
	ProfileVersion           string                        `json:"profile_version"`
	ProfileDigest            string                        `json:"profile_digest"`
	SourceProfilePackRef     string                        `json:"source_profile_pack_ref"`
	SourceProfilePackVersion string                        `json:"source_profile_pack_version"`
	SourceProfilePackDigest  string                        `json:"source_profile_pack_digest"`
	HomeFiles                []profilepack.LibraryHomeFile `json:"home_files"`
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

func applyLibraryProfileToHome(homeDir, agentID string, selector libraryProfileSelector) (*libraryMaterializeResponse, []string, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, nil, fmt.Errorf("agent id is required for Library binding")
	}
	var materialized *libraryMaterializeResponse
	var written []string
	err := withWorkingDir(homeDir, func() error {
		imported, err := callLibraryImportToShelf(selector)
		if err != nil {
			return fmt.Errorf("library import-to-shelf: %w", err)
		}
		if err := callLibraryBind(strings.TrimSpace(agentID), imported); err != nil {
			return fmt.Errorf("library bind: %w", err)
		}
		materialized, err = callLibraryMaterialize(strings.TrimSpace(agentID))
		if err != nil {
			return fmt.Errorf("library materialize: %w", err)
		}
		if err := validateLibraryMaterializeHome(materialized); err != nil {
			return err
		}
		written, err = profilepack.WriteLibraryHomeFiles(homeDir, materialized.HomeFiles, false)
		return err
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

func callLibraryMaterialize(agentID string) (*libraryMaterializeResponse, error) {
	body, err := executeLibraryToolBody([]string{"materialize", "--agent_id", agentID, "--runtime_kind", "claude-code", "--target", "local"})
	if err != nil {
		return nil, err
	}
	var out libraryMaterializeResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode library materialize response: %w", err)
	}
	return &out, nil
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

func validateLibraryMaterializeHome(result *libraryMaterializeResponse) error {
	if result == nil {
		return fmt.Errorf("library materialize response is required")
	}
	seen := map[string]bool{}
	for _, file := range result.HomeFiles {
		seen[filepath.ToSlash(strings.TrimSpace(file.Path))] = true
	}
	for _, required := range []string{"AGENTS.md", "CLAUDE.md", ".aw/profile/ref.json", ".aw/profile/profile.yaml", ".aw/profile/instructions.md"} {
		if !seen[required] {
			return fmt.Errorf("library materialize response missing %s", required)
		}
	}
	return nil
}
