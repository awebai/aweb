package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/awebai/aw/internal/teamblueprint"
	"github.com/spf13/cobra"
)

var blueprintInspectJSON bool

var blueprintCmd = &cobra.Command{
	Use:   "blueprint",
	Short: "Inspect and apply team blueprints",
}

var blueprintInspectCmd = &cobra.Command{
	Use:   "inspect <source>",
	Short: "Inspect a team blueprint without applying it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBlueprintInspect(cmd.OutOrStdout(), args[0], blueprintInspectJSON)
	},
}

func init() {
	blueprintInspectCmd.Flags().BoolVar(&blueprintInspectJSON, "json", false, "Print machine-readable JSON")
	blueprintCmd.AddCommand(blueprintInspectCmd)
	rootCmd.AddCommand(blueprintCmd)
}

func runBlueprintInspect(out io.Writer, source string, jsonOut bool) error {
	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("blueprint source is required")
	}
	if strings.Contains(source, "://") || strings.HasPrefix(source, "git@") {
		return fmt.Errorf("remote blueprint sources are not supported yet; use a local directory")
	}
	bp, err := teamblueprint.LoadLocalDir(source)
	if err != nil {
		return err
	}
	plan := teamblueprint.InspectPlan(bp)
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

func printBlueprintPlan(out io.Writer, plan teamblueprint.Plan) {
	fmt.Fprintf(out, "Blueprint: %s (%s)\n", plan.Blueprint.Name, plan.Blueprint.ID)
	fmt.Fprintf(out, "Version: %s\n", plan.Blueprint.Version)
	fmt.Fprintf(out, "Source: %s %s\n", plan.Source.Kind, plan.Source.Ref)
	fmt.Fprintf(out, "Digest: %s\n", plan.Source.Digest)
	if strings.TrimSpace(plan.Blueprint.Summary) != "" {
		fmt.Fprintf(out, "Summary: %s\n", plan.Blueprint.Summary)
	}
	fmt.Fprintln(out, "\nAgents:")
	for _, agent := range plan.Agents {
		fmt.Fprintf(out, "  - %s: profile %s@%s, default name %s, count %d (range %d-%d)\n", agent.Role, agent.ProfileID, agent.ProfileVersion, agent.DefaultAgentName, agent.DefaultCount, agent.Min, agent.Max)
		if len(agent.RuntimeHints) > 0 {
			fmt.Fprintf(out, "    runtimes: %s\n", strings.Join(agent.RuntimeHints, ", "))
		}
		if strings.TrimSpace(agent.Purpose) != "" {
			fmt.Fprintf(out, "    purpose: %s\n", agent.Purpose)
		}
	}
	if len(plan.RequestedApps) > 0 {
		fmt.Fprintln(out, "\nRequested apps/scopes:")
		for _, app := range plan.RequestedApps {
			if len(app.Scopes) == 0 {
				fmt.Fprintf(out, "  - %s\n", app.App)
				continue
			}
			fmt.Fprintf(out, "  - %s: %s\n", app.App, strings.Join(app.Scopes, ", "))
		}
	}
	if len(plan.EventSubscriptions) > 0 {
		fmt.Fprintln(out, "\nEvent subscriptions:")
		for _, sub := range plan.EventSubscriptions {
			event := sub.Event
			if event == "" {
				event = sub.Type
			}
			app := sub.App
			if app == "" {
				app = "app"
			}
			fmt.Fprintf(out, "  - %s.%s\n", app, event)
		}
	}
	if len(plan.ApprovalPolicy.RequireHumanApproval) > 0 {
		fmt.Fprintf(out, "\nApproval required: %s\n", strings.Join(plan.ApprovalPolicy.RequireHumanApproval, ", "))
	}
	if len(plan.CodeArtifacts) > 0 {
		fmt.Fprintln(out, "\nCode artifacts:")
		for _, artifact := range plan.CodeArtifacts {
			fmt.Fprintf(out, "  - %s (%s)\n", artifact.Path, artifact.Kind)
		}
	}
	fmt.Fprintln(out, "\nFiles that would be written:")
	for _, path := range plan.FilesWouldWrite {
		fmt.Fprintf(out, "  - %s\n", path)
	}
	if len(plan.CommandsWouldRun) == 0 {
		fmt.Fprintln(out, "\nCommands that would run: none (dry-run inspect)")
	} else {
		fmt.Fprintln(out, "\nCommands that would run:")
		for _, command := range plan.CommandsWouldRun {
			fmt.Fprintf(out, "  - %s\n", command)
		}
	}
	fmt.Fprintln(out, "\nRequired human decisions:")
	for _, decision := range plan.RequiredHumanDecisions {
		fmt.Fprintf(out, "  - %s\n", decision)
	}
}
