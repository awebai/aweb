package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/awebai/aw/internal/blueprint"
	"github.com/spf13/cobra"
)

var (
	blueprintInspectJSON       bool
	blueprintMaterializeJSON   bool
	blueprintMaterializeID     string
	blueprintMaterializeTarget string
	blueprintMaterializeForce  bool
)

var blueprintCmd = &cobra.Command{
	Use:   "blueprint",
	Short: "Inspect and manage Library blueprints",
}

var blueprintInspectCmd = &cobra.Command{
	Use:   "inspect <source>",
	Short: "Inspect a blueprint without importing or materializing it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBlueprintInspect(cmd.OutOrStdout(), args[0], blueprintInspectJSON)
	},
}

var blueprintMaterializeCmd = &cobra.Command{
	Use:   "materialize <source>",
	Short: "Materialize one local blueprint profile into a local agent home",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBlueprintMaterialize(cmd.OutOrStdout(), args[0], blueprintMaterializeID, blueprintMaterializeTarget, blueprintMaterializeForce, blueprintMaterializeJSON)
	},
}

func init() {
	blueprintInspectCmd.Flags().BoolVar(&blueprintInspectJSON, "json", false, "Print machine-readable JSON")
	blueprintMaterializeCmd.Flags().StringVar(&blueprintMaterializeID, "profile", "", "Profile id to materialize")
	blueprintMaterializeCmd.Flags().StringVar(&blueprintMaterializeTarget, "target", "", "Target local agent home directory")
	blueprintMaterializeCmd.Flags().BoolVar(&blueprintMaterializeForce, "force", false, "Overwrite existing materialized files")
	blueprintMaterializeCmd.Flags().BoolVar(&blueprintMaterializeJSON, "json", false, "Print machine-readable JSON")
	blueprintCmd.AddCommand(blueprintInspectCmd)
	blueprintCmd.AddCommand(blueprintMaterializeCmd)
	rootCmd.AddCommand(blueprintCmd)
}

func runBlueprintInspect(out io.Writer, source string, jsonOut bool) error {
	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("blueprint source is required")
	}
	kind, err := classifyBlueprintInspectSource(source)
	if err != nil {
		return err
	}
	if kind != "local_dir" {
		return fmt.Errorf("Library/git blueprint sources are not supported yet; use a local blueprint directory")
	}
	bp, err := blueprint.LoadLocalDir(source)
	if err != nil {
		return err
	}
	plan := blueprint.InspectPlan(bp)
	if jsonOut {
		encoded, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", encoded)
		return err
	}
	printBlueprintPlan(out, plan)
	return nil
}

func classifyBlueprintInspectSource(source string) (string, error) {
	source = strings.TrimSpace(source)
	if strings.Contains(source, "://") || strings.HasPrefix(source, "git@") || isSSHLikeBlueprintRef(source) {
		return "future_ref", nil
	}
	info, err := os.Stat(source)
	if err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("blueprint source %s is not a directory", source)
		}
		return "local_dir", nil
	}
	if isExplicitLocalPath(source) {
		return "", fmt.Errorf("blueprint source %s not found", source)
	}
	return "future_ref", nil
}

func isExplicitLocalPath(source string) bool {
	return strings.HasPrefix(source, ".") || strings.HasPrefix(source, string(os.PathSeparator)) || strings.HasPrefix(source, "~")
}

func isSSHLikeBlueprintRef(source string) bool {
	at := strings.Index(source, "@")
	colon := strings.Index(source, ":")
	return at > 0 && colon > at
}

func runBlueprintMaterialize(out io.Writer, source, profileID, target string, force, jsonOut bool) error {
	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("blueprint source is required")
	}
	kind, err := classifyBlueprintInspectSource(source)
	if err != nil {
		return err
	}
	if kind != "local_dir" {
		return fmt.Errorf("Library/git blueprint sources are not supported yet; use a local blueprint directory")
	}
	result, err := blueprint.MaterializeLocalProfile(blueprint.MaterializeOptions{SourceDir: source, ProfileID: profileID, TargetDir: target, Force: force})
	if err != nil {
		return err
	}
	if jsonOut {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", encoded)
		return err
	}
	fmt.Fprintf(out, "Materialized profile %s@%s into %s\n", result.ProfileRef, result.ProfileVersion, result.TargetDir)
	fmt.Fprintf(out, "Profile digest: %s\n", result.ProfileDigest)
	fmt.Fprintf(out, "Source blueprint: %s@%s (%s)\n", result.SourceBlueprintRef, result.SourceBlueprintVersion, result.SourceBlueprintDigest)
	fmt.Fprintln(out, "Files written:")
	for _, path := range result.FilesWritten {
		fmt.Fprintf(out, "  - %s\n", path)
	}
	return nil
}

func printBlueprintPlan(out io.Writer, plan blueprint.Plan) {
	fmt.Fprintf(out, "Blueprint: %s (%s)\n", plan.Blueprint.Name, plan.Blueprint.ID)
	fmt.Fprintf(out, "Version: %s\n", plan.Blueprint.Version)
	fmt.Fprintf(out, "Source: %s %s\n", plan.Source.Kind, plan.Source.Ref)
	fmt.Fprintf(out, "Digest: %s (%s)\n", plan.Source.Digest, plan.Source.DigestScope)
	if strings.TrimSpace(plan.Blueprint.Summary) != "" {
		fmt.Fprintf(out, "Summary: %s\n", plan.Blueprint.Summary)
	}
	if strings.TrimSpace(plan.Blueprint.Description) != "" {
		fmt.Fprintf(out, "Description: %s\n", plan.Blueprint.Description)
	}
	if len(plan.Blueprint.ExpectedApps) > 0 {
		fmt.Fprintf(out, "Expected apps (setup hints, not grants): %s\n", strings.Join(plan.Blueprint.ExpectedApps, ", "))
	}
	if len(plan.Blueprint.RuntimeHints) > 0 {
		fmt.Fprintf(out, "Runtime hints: %s\n", strings.Join(plan.Blueprint.RuntimeHints, ", "))
	}
	fmt.Fprintln(out, "\nProfiles:")
	for _, profile := range plan.Profiles {
		fmt.Fprintf(out, "  - %s: %s@%s, count %d (range %d-%d)\n", profile.ID, profile.Name, profile.Version, profile.DefaultCount, profile.Min, profile.Max)
		fmt.Fprintf(out, "    mission: %s\n", profile.Mission)
		if len(profile.ExpectedApps) > 0 {
			fmt.Fprintf(out, "    expected apps (setup hints, not grants): %s\n", strings.Join(profile.ExpectedApps, ", "))
		}
		if len(profile.RuntimeAssumptions) > 0 {
			fmt.Fprintf(out, "    runtime assumptions: %s\n", strings.Join(profile.RuntimeAssumptions, ", "))
		}
		fmt.Fprintf(out, "    instructions: %s\n", profile.MaterializationPreview.InstructionsPath)
		if len(profile.MaterializationPreview.Skills) > 0 {
			fmt.Fprintln(out, "    skills:")
			for _, skill := range profile.MaterializationPreview.Skills {
				fmt.Fprintf(out, "      - %s\n", skill.Path)
			}
		}
		if len(profile.MaterializationPreview.Artifacts) > 0 {
			fmt.Fprintln(out, "    artifacts:")
			for _, artifact := range profile.MaterializationPreview.Artifacts {
				if artifact.Kind != "" {
					fmt.Fprintf(out, "      - %s (%s)\n", artifact.Path, artifact.Kind)
				} else {
					fmt.Fprintf(out, "      - %s\n", artifact.Path)
				}
			}
		}
	}
	fmt.Fprintln(out, "\nOptional Library import preview (separate future step; inspect uploads nothing):")
	fmt.Fprintf(out, "  optional layer: %t\n", plan.ImportPreview.OptionalLayer)
	fmt.Fprintf(out, "  requires Library subscription: %t\n", plan.ImportPreview.RequiresLibrarySubscription)
	fmt.Fprintf(out, "  endpoint: %s\n", plan.ImportPreview.LibraryEndpoint)
	fmt.Fprintf(out, "  would upload on import: %t\n", plan.ImportPreview.WouldUploadOnImport)
	fmt.Fprintf(out, "  payload digest: %s\n", plan.ImportPreview.PayloadDigest)
	fmt.Fprintln(out, "  payload files:")
	for _, path := range plan.ImportPreview.PayloadFiles {
		fmt.Fprintf(out, "    - %s\n", path)
	}
	fmt.Fprintln(out, "\nOptional materialization preview (separate future step; inspect writes nothing):")
	fmt.Fprintf(out, "  optional layer: %t\n", plan.MaterializationPreview.OptionalLayer)
	fmt.Fprintf(out, "  target: %s\n", plan.MaterializationPreview.Target)
	fmt.Fprintf(out, "  would record .aw profile refs on materialize: %t\n", plan.MaterializationPreview.WouldRecordAWProfileRefsOnMaterialize)
	if len(plan.FilesWouldWrite) == 0 {
		fmt.Fprintln(out, "\nFiles that would be written by inspect: none")
	} else {
		fmt.Fprintln(out, "\nFiles that would be written by inspect:")
		for _, path := range plan.FilesWouldWrite {
			fmt.Fprintf(out, "  - %s\n", path)
		}
	}
	if len(plan.CommandsWouldRun) == 0 {
		fmt.Fprintln(out, "Commands that would run: none")
	} else {
		fmt.Fprintln(out, "Commands that would run:")
		for _, command := range plan.CommandsWouldRun {
			fmt.Fprintf(out, "  - %s\n", command)
		}
	}
	fmt.Fprintln(out, "\nRequired human decisions for inspect: none")
	if len(plan.OptionalNextSteps) > 0 {
		fmt.Fprintln(out, "\nOptional next steps:")
		for _, step := range plan.OptionalNextSteps {
			fmt.Fprintf(out, "  - %s\n", step)
		}
	}
}
