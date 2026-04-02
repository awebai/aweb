package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var instructionsCmd = &cobra.Command{
	Use:   "instructions",
	Short: "Read and manage shared project instructions",
}

var instructionsShowCmd = &cobra.Command{
	Use:   "show [project-instructions-id]",
	Short: "Show shared project instructions",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runInstructionsShow,
}

var instructionsHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "List shared project instructions history",
	RunE:  runInstructionsHistory,
}

var instructionsSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Create and activate a new shared project instructions version",
	RunE:  runInstructionsSet,
}

var instructionsActivateCmd = &cobra.Command{
	Use:   "activate <project-instructions-id>",
	Short: "Activate an existing shared project instructions version",
	Args:  cobra.ExactArgs(1),
	RunE:  runInstructionsActivate,
}

var instructionsResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset shared project instructions to the server default",
	RunE:  runInstructionsReset,
}

var (
	instructionsHistoryLimit int
	instructionsSetBody      string
	instructionsSetBodyFile  string
)

type projectInstructionsShowOutput struct {
	RequestedID         string                                  `json:"requested_id,omitempty"`
	IsActive            bool                                    `json:"is_active"`
	ProjectInstructions *aweb.ActiveProjectInstructionsResponse `json:"project_instructions"`
}

type projectInstructionsSetOutput struct {
	ProjectInstructionsID string `json:"project_instructions_id"`
	Version               int    `json:"version"`
	Activated             bool   `json:"activated"`
}

type projectInstructionsActivateOutput struct {
	ProjectInstructionsID string `json:"project_instructions_id"`
	Activated             bool   `json:"activated"`
}

func init() {
	instructionsHistoryCmd.Flags().IntVar(&instructionsHistoryLimit, "limit", 20, "Max instruction versions")
	instructionsSetCmd.Flags().StringVar(&instructionsSetBody, "body", "", "Instructions markdown body")
	instructionsSetCmd.Flags().StringVar(&instructionsSetBodyFile, "body-file", "", "Read instructions markdown from file ('-' for stdin)")

	instructionsCmd.AddCommand(instructionsShowCmd)
	instructionsCmd.AddCommand(instructionsHistoryCmd)
	instructionsCmd.AddCommand(instructionsSetCmd)
	instructionsCmd.AddCommand(instructionsActivateCmd)
	instructionsCmd.AddCommand(instructionsResetCmd)
	rootCmd.AddCommand(instructionsCmd)
	instructionsCmd.GroupID = groupCoordination
}

func runInstructionsShow(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	requestedID := ""
	var resp *aweb.ActiveProjectInstructionsResponse
	isActive := true
	if len(args) == 1 {
		requestedID = strings.TrimSpace(args[0])
		resp, err = client.GetProjectInstructions(ctx, requestedID)
		if err == nil {
			active, activeErr := client.ActiveProjectInstructions(ctx)
			if activeErr != nil {
				err = activeErr
			} else {
				isActive = requestedID == active.ProjectInstructionsID ||
					requestedID == active.ActiveProjectInstructionsID
			}
		}
	} else {
		resp, err = client.ActiveProjectInstructions(ctx)
	}
	if err != nil {
		return err
	}

	printOutput(projectInstructionsShowOutput{
		RequestedID:         requestedID,
		IsActive:            isActive,
		ProjectInstructions: resp,
	}, formatProjectInstructionsShow)
	return nil
}

func runInstructionsHistory(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ProjectInstructionsHistory(ctx, instructionsHistoryLimit)
	if err != nil {
		return err
	}
	printOutput(resp, formatProjectInstructionsHistory)
	return nil
}

func runInstructionsSet(cmd *cobra.Command, args []string) error {
	body, err := resolveInstructionsBody(cmd.InOrStdin(), instructionsSetBody, instructionsSetBodyFile)
	if err != nil {
		return err
	}

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	active, err := client.ActiveProjectInstructions(ctx)
	if err != nil {
		return err
	}

	created, err := client.CreateProjectInstructions(ctx, &aweb.CreateProjectInstructionsRequest{
		Document: aweb.ProjectInstructionsDocument{
			BodyMD: body,
			Format: "markdown",
		},
		BaseProjectInstructionsID: active.ProjectInstructionsID,
	})
	if err != nil {
		return err
	}

	if _, err := client.ActivateProjectInstructions(ctx, created.ProjectInstructionsID); err != nil {
		return err
	}

	printOutput(projectInstructionsSetOutput{
		ProjectInstructionsID: created.ProjectInstructionsID,
		Version:               created.Version,
		Activated:             true,
	}, formatProjectInstructionsSet)
	return nil
}

func runInstructionsActivate(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActivateProjectInstructions(ctx, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}

	printOutput(projectInstructionsActivateOutput{
		ProjectInstructionsID: resp.ActiveProjectInstructionsID,
		Activated:             resp.Activated,
	}, formatProjectInstructionsActivate)
	return nil
}

func runInstructionsReset(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ResetProjectInstructions(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatProjectInstructionsReset)
	return nil
}

func resolveInstructionsBody(stdin io.Reader, body, bodyFile string) (string, error) {
	body = strings.TrimSpace(body)
	bodyFile = strings.TrimSpace(bodyFile)

	switch {
	case body != "" && bodyFile != "":
		return "", usageError("use only one of --body or --body-file")
	case body != "":
		return body, nil
	case bodyFile == "":
		return "", usageError("missing required flag: --body or --body-file")
	case bodyFile == "-":
		data, err := io.ReadAll(stdin)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	default:
		data, err := os.ReadFile(bodyFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
}

func formatProjectInstructionsShow(v any) string {
	out := v.(projectInstructionsShowOutput)
	if out.ProjectInstructions == nil {
		return "No active project instructions.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Project Instructions v%d", out.ProjectInstructions.Version))
	if out.IsActive {
		sb.WriteString(" (active)")
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("ID: %s\n", out.ProjectInstructions.ProjectInstructionsID))

	body := strings.TrimSpace(out.ProjectInstructions.Document.BodyMD)
	if body == "" {
		sb.WriteString("\n(empty)\n")
		return sb.String()
	}
	sb.WriteString("\n")
	sb.WriteString(body)
	sb.WriteString("\n")
	return sb.String()
}

func formatProjectInstructionsHistory(v any) string {
	out := v.(*aweb.ProjectInstructionsHistoryResponse)
	if out == nil || len(out.ProjectInstructionsVersions) == 0 {
		return "No project instructions versions.\n"
	}

	var sb strings.Builder
	for _, item := range out.ProjectInstructionsVersions {
		status := "inactive"
		if item.IsActive {
			status = "active"
		}
		sb.WriteString(fmt.Sprintf("v%d\t%s\t%s\t%s", item.Version, status, item.CreatedAt, item.ProjectInstructionsID))
		if item.CreatedByWorkspaceID != nil && strings.TrimSpace(*item.CreatedByWorkspaceID) != "" {
			sb.WriteString("\t" + strings.TrimSpace(*item.CreatedByWorkspaceID))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatProjectInstructionsSet(v any) string {
	out := v.(projectInstructionsSetOutput)
	return fmt.Sprintf("Activated project instructions v%d (%s)\n", out.Version, out.ProjectInstructionsID)
}

func formatProjectInstructionsActivate(v any) string {
	out := v.(projectInstructionsActivateOutput)
	return fmt.Sprintf("Activated project instructions %s\n", out.ProjectInstructionsID)
}

func formatProjectInstructionsReset(v any) string {
	out := v.(*aweb.ResetProjectInstructionsResponse)
	if out == nil {
		return "Project instructions reset.\n"
	}
	return fmt.Sprintf("Reset project instructions to default (v%d, %s)\n", out.Version, out.ActiveProjectInstructionsID)
}
