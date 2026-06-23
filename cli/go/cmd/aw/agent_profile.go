package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var agentProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Inspect the Library profile recorded in a local agent home",
}

var agentProfileShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show the recorded profile ref/snapshot (.aw/profile/ref.json) for a materialized agent",
	Long: "Show the Library profile a local agent home was materialized from - the blueprint and " +
		"profile refs, versions, and content digests recorded in .aw/profile/ref.json. This is what " +
		"`aw team refresh` updates and what the materialize seam records; it never asks a remote service " +
		"which profile is in use.",
	Args: cobra.ExactArgs(1),
	RunE: runAgentProfileShow,
}

// recordedProfileRef mirrors the .aw/profile/ref.json a materialize writes
// (internal/blueprint materializedProfileRef).
type recordedProfileRef struct {
	ProfileDigest          string `json:"profile_digest"`
	ProfileRef             string `json:"profile_ref"`
	ProfileVersion         string `json:"profile_version"`
	SourceBlueprintDigest  string `json:"source_blueprint_digest,omitempty"`
	SourceBlueprintRef     string `json:"source_blueprint_ref,omitempty"`
	SourceBlueprintVersion string `json:"source_blueprint_version,omitempty"`
}

func runAgentProfileShow(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	home, err := resolveAgentHome(name)
	if err != nil {
		return err
	}
	refPath := filepath.Join(home, ".aw", "profile", "ref.json")
	data, err := os.ReadFile(refPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no recorded profile for %q: %s not found (materialize it from a Library profile first, e.g. `aw team add %s@<blueprint>/<profile>`)", name, refPath, name)
		}
		return fmt.Errorf("read %s: %w", refPath, err)
	}
	var ref recordedProfileRef
	if err := json.Unmarshal(data, &ref); err != nil {
		return fmt.Errorf("parse %s: %w", refPath, err)
	}

	out := cmd.OutOrStdout()
	if jsonFlag {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(ref)
	}
	fmt.Fprintf(out, "Agent:     %s\n", name)
	if ref.SourceBlueprintRef != "" {
		fmt.Fprintf(out, "Blueprint: %s@%s (%s)\n", ref.SourceBlueprintRef, ref.SourceBlueprintVersion, ref.SourceBlueprintDigest)
	}
	fmt.Fprintf(out, "Profile:   %s@%s (%s)\n", ref.ProfileRef, ref.ProfileVersion, ref.ProfileDigest)
	return nil
}

func init() {
	agentProfileShowCmd.Flags().StringVar(&agentHomeFlag, "home", "", "Agent home directory override (default: agents/instances/<name>)")
	agentProfileCmd.AddCommand(agentProfileShowCmd)
	agentCmd.AddCommand(agentProfileCmd)
}
