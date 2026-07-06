package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/awebai/aw/internal/blueprint"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
)

var teamRefreshRuntime string

var teamHumanRefreshCmd = &cobra.Command{
	Use:   "refresh <name>",
	Short: "Re-materialize a team member's home from the latest version of its Library profile",
	Long: "Re-materialize agents/instances/<name> from the latest version of the profile it was\n" +
		"materialized from on the team's private Library shelf. This closes the learning loop: an\n" +
		"approved profile proposal mints a new shelf version, and `aw team refresh` re-applies it\n" +
		"locally and updates .aw/profile/ref.json - so the agent picks up the team's own improvement.\n" +
		"It reads the recorded profile ref locally and never asks a remote service which profile to use.\n\n" +
		"Upstream blueprint updates are a separate, composable step: run `aw library update-from-source`\n" +
		"first to pull them onto the shelf, then `aw team refresh` to re-materialize.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamRefresh,
}

// libraryShelfProfileResponse is the team's private shelf profile content
// (get-shelf-profile), mirroring the catalog get-profile shape plus the source
// provenance, so the materialize path is reused unchanged.
type libraryShelfProfileResponse struct {
	ProfileRef             string                                `json:"profile_ref"`
	Version                string                                `json:"version"`
	Digest                 string                                `json:"digest"`
	SourceBlueprintRef     string                                `json:"source_blueprint_ref"`
	SourceBlueprintVersion string                                `json:"source_blueprint_version"`
	SourceBlueprintDigest  string                                `json:"source_blueprint_digest"`
	Files                  []blueprint.LibraryProfilePayloadFile `json:"files"`
}

func runTeamRefresh(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	home, err := resolveAgentHome(name)
	if err != nil {
		return err
	}
	old, err := readRecordedProfileRef(home)
	if err != nil {
		return err
	}
	runtimeKind, err := normalizeMaterializeRuntimeKind(firstNonEmptyLibraryValue(teamRefreshRuntime, "claude-code"))
	if err != nil {
		return err
	}
	result, err := refreshLibraryProfileInHome(home, name, old, runtimeKind)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if jsonFlag {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	if result.ProfileVersion == old.ProfileVersion && result.ProfileDigest == old.ProfileDigest {
		fmt.Fprintf(out, "%s is already at the latest shelf version: %s@%s\n", name, result.ProfileRef, result.ProfileVersion)
		return nil
	}
	fmt.Fprintf(out, "Refreshed %s: %s@%s -> @%s\n", name, result.ProfileRef, old.ProfileVersion, result.ProfileVersion)
	fmt.Fprintf(out, "  profile digest: %s -> %s\n", old.ProfileDigest, result.ProfileDigest)
	fmt.Fprintf(out, "  re-materialized %d files\n", len(result.FilesWritten))
	return nil
}

func readRecordedProfileRef(home string) (recordedProfileRef, error) {
	var ref recordedProfileRef
	refPath := filepath.Join(home, ".aw", "profile", "ref.json")
	data, err := os.ReadFile(refPath)
	if err != nil {
		if os.IsNotExist(err) {
			base := filepath.Base(home)
			return ref, fmt.Errorf("%s has no recorded profile (%s not found); materialize it first, e.g. `aw team add %s@<blueprint>/<profile>`", base, refPath, base)
		}
		return ref, fmt.Errorf("read %s: %w", refPath, err)
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		return ref, fmt.Errorf("parse %s: %w", refPath, err)
	}
	if strings.TrimSpace(ref.ProfileRef) == "" {
		return ref, fmt.Errorf("%s has no profile_ref; cannot refresh", refPath)
	}
	return ref, nil
}

// refreshLibraryProfileInHome re-materializes the home from its pinned source.
// Public-blueprint pins (library_url present) refresh directly from the pinned
// provider; legacy shelf pins (no library_url) keep using the private shelf
// plugin path.
func refreshLibraryProfileInHome(homeDir, agentID string, old recordedProfileRef, runtimeKind string) (*blueprint.MaterializeResult, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, fmt.Errorf("agent id is required for Library refresh")
	}
	if strings.TrimSpace(old.LibraryURL) != "" {
		return refreshPublicLibraryProfileInHome(homeDir, old, runtimeKind)
	}
	return refreshShelfLibraryProfileInHome(homeDir, old, runtimeKind)
}

func refreshPublicLibraryProfileInHome(homeDir string, old recordedProfileRef, runtimeKind string) (*blueprint.MaterializeResult, error) {
	selector := libraryProfileSelector{
		LibraryURL:         strings.TrimSpace(old.LibraryURL),
		SourceBlueprintRef: strings.TrimSpace(old.SourceBlueprintRef),
		ProfileRef:         strings.TrimSpace(old.ProfileRef),
		RuntimeKind:        runtimeKind,
	}
	if selector.SourceBlueprintRef == "" {
		return nil, fmt.Errorf("recorded public profile has no source_blueprint_ref; cannot refresh from pinned library_url")
	}
	profile, err := fetchPublicLibraryProfile(context.Background(), selector)
	if err != nil {
		return nil, fmt.Errorf("library public get-profile: %w", err)
	}
	computedDigest, err := blueprint.ValidateLibraryProfilePayloadDigest(blueprint.ValidateLibraryProfilePayloadOptions{
		ProfileRef:     profile.ProfileRef,
		ProfileVersion: profile.Version,
		ProfileDigest:  profile.Digest,
		Files:          profile.Files,
	})
	if err != nil {
		return nil, fmt.Errorf("library public profile integrity: %w", err)
	}
	// Only trust the recomputed digest. The provider-claimed digest was checked
	// above, but the unchanged no-op decision is anchored on local bytes.
	if computedDigest == strings.TrimSpace(old.ProfileDigest) {
		return &blueprint.MaterializeResult{
			ProfileRef:             strings.TrimSpace(old.ProfileRef),
			ProfileVersion:         strings.TrimSpace(old.ProfileVersion),
			ProfileDigest:          strings.TrimSpace(old.ProfileDigest),
			SourceBlueprintRef:     strings.TrimSpace(old.SourceBlueprintRef),
			SourceBlueprintVersion: strings.TrimSpace(old.SourceBlueprintVersion),
			TargetDir:              homeDir,
			FilesWritten:           nil,
		}, nil
	}
	return materializeAndPruneLibraryProfileInHome(homeDir, old, blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir:        homeDir,
		LibraryURL:       selector.LibraryURL,
		BlueprintRef:     profile.BlueprintRef,
		BlueprintVersion: profile.BlueprintVersion,
		ProfileRef:       profile.ProfileRef,
		ProfileVersion:   profile.Version,
		ProfileDigest:    profile.Digest,
		RuntimeKind:      runtimeKind,
		Files:            profile.Files,
		Force:            true,
	})
}

func refreshShelfLibraryProfileInHome(homeDir string, old recordedProfileRef, runtimeKind string) (*blueprint.MaterializeResult, error) {
	var shelf *libraryShelfProfileResponse
	err := withWorkingDir(homeDir, func() error {
		var err error
		shelf, err = callLibraryGetShelfProfile(old.ProfileRef)
		if err != nil {
			return fmt.Errorf("library get-shelf-profile: %w", err)
		}
		// The refresh is pinned to the LOCALLY recorded profile: the recorded ref
		// decides which profile to re-materialize, never the remote response. Refuse
		// a response whose profile_ref differs, so a bug/proxy/test double cannot
		// redirect the refresh and rewrite ref.json to a different profile.
		if shelf.ProfileRef != old.ProfileRef {
			return fmt.Errorf("library returned profile_ref %q for a refresh of %q; refusing to rewrite the recorded profile with a different one", shelf.ProfileRef, old.ProfileRef)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return materializeAndPruneLibraryProfileInHome(homeDir, old, blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir:        homeDir,
		BlueprintRef:     firstNonEmptyLibraryValue(shelf.SourceBlueprintRef, old.SourceBlueprintRef),
		BlueprintVersion: firstNonEmptyLibraryValue(shelf.SourceBlueprintVersion, old.SourceBlueprintVersion),
		BlueprintDigest:  firstNonEmptyLibraryValue(shelf.SourceBlueprintDigest, old.SourceBlueprintDigest),
		ProfileRef:       old.ProfileRef,
		ProfileVersion:   shelf.Version,
		ProfileDigest:    shelf.Digest,
		RuntimeKind:      runtimeKind,
		Files:            shelf.Files,
		Force:            true,
	})
}

func materializeAndPruneLibraryProfileInHome(homeDir string, old recordedProfileRef, opts blueprint.MaterializeLibraryProfilePayloadOptions) (*blueprint.MaterializeResult, error) {
	var materialized *blueprint.MaterializeResult
	err := withWorkingDir(homeDir, func() error {
		var mErr error
		materialized, mErr = blueprint.MaterializeLibraryProfilePayload(opts)
		if mErr != nil {
			return fmt.Errorf("local profile materialize: %w", mErr)
		}
		return pruneRemovedManagedProfileFiles(homeDir, old.ManagedSet, materialized.FilesWritten)
	})
	if err != nil {
		return nil, err
	}
	return materialized, nil
}

func pruneRemovedManagedProfileFiles(homeDir string, oldManaged, newManaged []string) error {
	if len(oldManaged) == 0 {
		return nil
	}
	newSet := map[string]bool{}
	for _, rel := range newManaged {
		newSet[filepath.ToSlash(strings.TrimSpace(rel))] = true
	}
	var remove []string
	for _, rel := range oldManaged {
		rel = filepath.ToSlash(strings.TrimSpace(rel))
		if rel == "" || newSet[rel] {
			continue
		}
		if err := validateManagedSetPath(rel); err != nil {
			return err
		}
		remove = append(remove, rel)
	}
	sort.Slice(remove, func(i, j int) bool { return len(remove[i]) > len(remove[j]) })
	for _, rel := range remove {
		path := filepath.Join(homeDir, filepath.FromSlash(rel))
		if err := pathpreflight.RejectSymlinkedExistingComponents(filepath.Dir(path), rel, pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("managed path %s is a directory; refusing to prune", rel)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func validateManagedSetPath(rel string) error {
	if rel == "" {
		return fmt.Errorf("managed path is required")
	}
	for _, r := range rel {
		if unicode.IsControl(r) {
			return fmt.Errorf("managed path %s contains control characters", rel)
		}
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.Contains(rel, "://") || strings.Contains(rel, "\\") {
		return fmt.Errorf("managed path %s is not a safe relative path", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("managed path %s is not a safe relative path", rel)
	}
	return nil
}

func callLibraryGetShelfProfile(profileRef string) (*libraryShelfProfileResponse, error) {
	body, err := executeLibraryToolBody([]string{"get-shelf-profile", "--profile_ref", profileRef, "--include", "files"}, nil)
	if err != nil {
		return nil, err
	}
	var out libraryShelfProfileResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode library get-shelf-profile response: %w", err)
	}
	if out.ProfileRef == "" || out.Version == "" || out.Digest == "" || len(out.Files) == 0 {
		return nil, fmt.Errorf("library get-shelf-profile response missing profile_ref/version/digest/files")
	}
	return &out, nil
}

func init() {
	teamHumanRefreshCmd.Flags().StringVar(&agentHomeFlag, "home", "", "Agent home directory override (default: agents/instances/<name>)")
	teamHumanRefreshCmd.Flags().StringVar(&teamRefreshRuntime, "runtime", "claude-code", "Runtime harness to re-materialize for (claude-code|codex|pi|local-shell)")
	teamHumanCmd.AddCommand(teamHumanRefreshCmd)
}
