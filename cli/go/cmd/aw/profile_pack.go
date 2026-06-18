package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/awebai/aw/internal/profilepack"
	"github.com/spf13/cobra"
)

var profilePackInspectJSON bool

var profilePackCmd = &cobra.Command{
	Use:   "profile-pack",
	Short: "Inspect and manage Library profile packs",
}

var profilePackInspectCmd = &cobra.Command{
	Use:   "inspect <source>",
	Short: "Inspect a profile pack without importing or materializing it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProfilePackInspect(cmd.OutOrStdout(), args[0], profilePackInspectJSON)
	},
}

func init() {
	profilePackInspectCmd.Flags().BoolVar(&profilePackInspectJSON, "json", false, "Print machine-readable JSON")
	profilePackCmd.AddCommand(profilePackInspectCmd)
	rootCmd.AddCommand(profilePackCmd)
}

func runProfilePackInspect(out io.Writer, source string, jsonOut bool) error {
	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("profile-pack source is required")
	}
	kind, err := classifyProfilePackInspectSource(source)
	if err != nil {
		return err
	}
	if kind != "local_dir" {
		return fmt.Errorf("Library/git profile-pack sources are not supported yet; use a local profile-pack directory")
	}
	pack, err := profilepack.LoadLocalDir(source)
	if err != nil {
		return err
	}
	plan := profilepack.InspectPlan(pack)
	if jsonOut {
		encoded, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", encoded)
		return err
	}
	printProfilePackPlan(out, plan)
	return nil
}

func classifyProfilePackInspectSource(source string) (string, error) {
	source = strings.TrimSpace(source)
	if strings.Contains(source, "://") || strings.HasPrefix(source, "git@") || isSSHLikeProfilePackRef(source) {
		return "future_ref", nil
	}
	info, err := os.Stat(source)
	if err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("profile-pack source %s is not a directory", source)
		}
		return "local_dir", nil
	}
	if isExplicitLocalPath(source) {
		return "", fmt.Errorf("profile-pack source %s not found", source)
	}
	return "future_ref", nil
}

func isExplicitLocalPath(source string) bool {
	return strings.HasPrefix(source, ".") || strings.HasPrefix(source, string(os.PathSeparator)) || strings.HasPrefix(source, "~")
}

func isSSHLikeProfilePackRef(source string) bool {
	at := strings.Index(source, "@")
	colon := strings.Index(source, ":")
	return at > 0 && colon > at
}

func printProfilePackPlan(out io.Writer, plan profilepack.Plan) {
	fmt.Fprintf(out, "Profile pack: %s (%s)\n", plan.ProfilePack.Name, plan.ProfilePack.ID)
	fmt.Fprintf(out, "Version: %s\n", plan.ProfilePack.Version)
	fmt.Fprintf(out, "Source: %s %s\n", plan.Source.Kind, plan.Source.Ref)
	fmt.Fprintf(out, "Digest: %s (%s)\n", plan.Source.Digest, plan.Source.DigestScope)
	if strings.TrimSpace(plan.ProfilePack.Summary) != "" {
		fmt.Fprintf(out, "Summary: %s\n", plan.ProfilePack.Summary)
	}
	if strings.TrimSpace(plan.ProfilePack.Description) != "" {
		fmt.Fprintf(out, "Description: %s\n", plan.ProfilePack.Description)
	}
	if len(plan.ProfilePack.ExpectedApps) > 0 {
		fmt.Fprintf(out, "Expected apps (setup hints, not grants): %s\n", strings.Join(plan.ProfilePack.ExpectedApps, ", "))
	}
	if len(plan.ProfilePack.RuntimeHints) > 0 {
		fmt.Fprintf(out, "Runtime hints: %s\n", strings.Join(plan.ProfilePack.RuntimeHints, ", "))
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
	fmt.Fprintln(out, "\nImport preview (separate future step; inspect uploads nothing):")
	fmt.Fprintf(out, "  endpoint: %s\n", plan.ImportPreview.LibraryEndpoint)
	fmt.Fprintf(out, "  would upload on import: %t\n", plan.ImportPreview.WouldUploadOnImport)
	fmt.Fprintf(out, "  payload digest: %s\n", plan.ImportPreview.PayloadDigest)
	fmt.Fprintln(out, "  payload files:")
	for _, path := range plan.ImportPreview.PayloadFiles {
		fmt.Fprintf(out, "    - %s\n", path)
	}
	fmt.Fprintln(out, "\nMaterialization preview (separate future step; inspect writes nothing):")
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
	fmt.Fprintln(out, "\nRequired human decisions:")
	for _, decision := range plan.RequiredHumanDecisions {
		fmt.Fprintf(out, "  - %s\n", decision)
	}
}
