package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var teamHumanAdoptCmd = &cobra.Command{
	Use:   "adopt <name>",
	Short: "Adopt a public-pinned agent profile onto the team's private Library shelf",
	Long: "Adopt a public-pinned agents/instances/<name> profile onto the team's private Library shelf.\n" +
		"This reads .aw/profile/ref.json, imports the pinned public blueprint/profile onto the\n" +
		"team shelf through the installed Library plugin, binds the agent, and re-points the\n" +
		"local pin to the shelf copy by removing library_url. After adopt, aw team refresh\n" +
		"uses the shelf path and can pick up approved team-local profile mints.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamAdopt,
}

type teamAdoptOutput struct {
	Status                 string `json:"status"`
	Agent                  string `json:"agent"`
	HomeDir                string `json:"home_dir"`
	ProfileRef             string `json:"profile_ref"`
	ProfileVersion         string `json:"profile_version"`
	ProfileDigest          string `json:"profile_digest"`
	SourceBlueprintRef     string `json:"source_blueprint_ref"`
	SourceBlueprintVersion string `json:"source_blueprint_version"`
	SourceBlueprintDigest  string `json:"source_blueprint_digest"`
}

func runTeamAdopt(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	home, err := resolveAgentHome(name)
	if err != nil {
		return err
	}
	old, err := readRecordedProfileRef(home)
	if err != nil {
		return err
	}
	out, err := adoptLibraryProfilePinToShelf(home, name, old)
	if err != nil {
		return err
	}
	if cmd == nil {
		cmd = &cobra.Command{}
	}
	if jsonFlag {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Adopted %s onto the team Library shelf: %s@%s\n", out.Agent, out.ProfileRef, out.ProfileVersion)
	fmt.Fprintf(cmd.OutOrStdout(), "  home: %s\n", out.HomeDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  source: %s@%s (%s)\n", out.SourceBlueprintRef, out.SourceBlueprintVersion, out.SourceBlueprintDigest)
	fmt.Fprintf(cmd.OutOrStdout(), "  .aw/profile/ref.json now points at the shelf (library_url removed); run `aw team refresh %s` to pick up approved shelf mints.\n", out.Agent)
	return nil
}

func adoptLibraryProfilePinToShelf(homeDir, agentID string, old recordedProfileRef) (teamAdoptOutput, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return teamAdoptOutput{}, usageError("agent name is required")
	}
	if strings.TrimSpace(old.LibraryURL) == "" {
		return teamAdoptOutput{}, usageError("%s is already shelf-pinned (ref.json has no library_url); run `aw team refresh %s` to apply approved shelf mints", agentID, agentID)
	}
	if strings.TrimSpace(old.SourceBlueprintRef) == "" || strings.TrimSpace(old.ProfileRef) == "" || strings.TrimSpace(old.ProfileVersion) == "" || strings.TrimSpace(old.ProfileDigest) == "" {
		return teamAdoptOutput{}, fmt.Errorf("%s has an incomplete public profile pin; need source_blueprint_ref, profile_ref, profile_version, and profile_digest in .aw/profile/ref.json", agentID)
	}
	selector := libraryProfileSelector{
		SourceBlueprintRef:     strings.TrimSpace(old.SourceBlueprintRef),
		SourceBlueprintVersion: strings.TrimSpace(old.SourceBlueprintVersion),
		ProfileRef:             strings.TrimSpace(old.ProfileRef),
		RuntimeKind:            strings.TrimSpace(old.RuntimeKind),
	}
	var imported *libraryImportToShelfResponse
	var bound *libraryBindResponse
	err := withWorkingDir(homeDir, func() error {
		var err error
		imported, err = callLibraryImportToShelfWithMissingErr(selector, missingLibraryPluginCommandError())
		if err != nil {
			return fmt.Errorf("library import-to-shelf: %w", err)
		}
		if err := validateImportedShelfCopyMatchesPin(old, imported); err != nil {
			return err
		}
		bound, err = callLibraryBind(agentID, imported)
		if err != nil {
			return fmt.Errorf("library bind: %w", err)
		}
		return validateBindMatchesImport(bound, imported)
	})
	if err != nil {
		return teamAdoptOutput{}, err
	}
	newRef := old
	newRef.LibraryURL = ""
	newRef.ProfileRef = strings.TrimSpace(imported.ProfileRef)
	newRef.ProfileVersion = strings.TrimSpace(imported.Version)
	newRef.ProfileDigest = strings.TrimSpace(imported.Digest)
	newRef.SourceBlueprintRef = strings.TrimSpace(imported.SourceBlueprintRef)
	newRef.SourceBlueprintVersion = strings.TrimSpace(imported.SourceBlueprintVersion)
	newRef.SourceBlueprintDigest = strings.TrimSpace(imported.SourceBlueprintDigest)
	if err := writeRecordedProfileRef(homeDir, newRef); err != nil {
		return teamAdoptOutput{}, err
	}
	return teamAdoptOutput{
		Status:                 "adopted",
		Agent:                  agentID,
		HomeDir:                homeDir,
		ProfileRef:             newRef.ProfileRef,
		ProfileVersion:         newRef.ProfileVersion,
		ProfileDigest:          newRef.ProfileDigest,
		SourceBlueprintRef:     newRef.SourceBlueprintRef,
		SourceBlueprintVersion: newRef.SourceBlueprintVersion,
		SourceBlueprintDigest:  newRef.SourceBlueprintDigest,
	}, nil
}

func validateImportedShelfCopyMatchesPin(old recordedProfileRef, imported *libraryImportToShelfResponse) error {
	if imported == nil {
		return fmt.Errorf("library import result is required")
	}
	checks := []struct {
		field string
		got   string
		want  string
	}{
		{"profile_ref", imported.ProfileRef, old.ProfileRef},
		{"profile_version", imported.Version, old.ProfileVersion},
		{"profile_digest", imported.Digest, old.ProfileDigest},
		{"source_blueprint_ref", imported.SourceBlueprintRef, old.SourceBlueprintRef},
	}
	if strings.TrimSpace(old.SourceBlueprintVersion) != "" {
		checks = append(checks, struct {
			field string
			got   string
			want  string
		}{"source_blueprint_version", imported.SourceBlueprintVersion, old.SourceBlueprintVersion})
	}
	for _, check := range checks {
		if strings.TrimSpace(check.got) != strings.TrimSpace(check.want) {
			return fmt.Errorf("library import-to-shelf did not preserve pinned %s: got %q, want %q; refusing to re-point local profile pin", check.field, check.got, check.want)
		}
	}
	return nil
}

func writeRecordedProfileRef(homeDir string, ref recordedProfileRef) error {
	refPath := filepath.Join(homeDir, ".aw", "profile", "ref.json")
	if err := os.MkdirAll(filepath.Dir(refPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(refPath, append(data, '\n'), 0o644)
}

func init() {
	teamHumanAdoptCmd.Flags().StringVar(&agentHomeFlag, "home", "", "Agent home directory override (default: agents/instances/<name>)")
	teamHumanCmd.AddCommand(teamHumanAdoptCmd)
}
