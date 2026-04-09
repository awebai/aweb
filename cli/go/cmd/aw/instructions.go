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
	Short: "Read and manage shared team instructions",
}

var instructionsShowCmd = &cobra.Command{
	Use:   "show [team-instructions-id]",
	Short: "Show shared team instructions",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runInstructionsShow,
}

var instructionsHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "List shared team instructions history",
	RunE:  runInstructionsHistory,
}

var instructionsSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Create and activate a new shared team instructions version",
	RunE:  runInstructionsSet,
}

var instructionsActivateCmd = &cobra.Command{
	Use:   "activate <team-instructions-id>",
	Short: "Activate an existing shared team instructions version",
	Args:  cobra.ExactArgs(1),
	RunE:  runInstructionsActivate,
}

var instructionsResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset shared team instructions to the server default",
	RunE:  runInstructionsReset,
}

var (
	instructionsHistoryLimit int
	instructionsSetBody      string
	instructionsSetBodyFile  string
)

type teamInstructionsShowOutput struct {
	RequestedID      string                               `json:"requested_id,omitempty"`
	IsActive         bool                                 `json:"is_active"`
	TeamInstructions *aweb.ActiveTeamInstructionsResponse `json:"team_instructions"`
}

type teamInstructionsSetOutput struct {
	TeamInstructionsID string `json:"team_instructions_id"`
	Version            int    `json:"version"`
	Activated          bool   `json:"activated"`
}

type teamInstructionsActivateOutput struct {
	TeamInstructionsID string `json:"team_instructions_id"`
	Activated          bool   `json:"activated"`
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
	var resp *aweb.ActiveTeamInstructionsResponse
	isActive := true
	if len(args) == 1 {
		requestedID = strings.TrimSpace(args[0])
		resp, err = client.GetTeamInstructions(ctx, requestedID)
		if err == nil {
			active, activeErr := client.ActiveTeamInstructions(ctx)
			if activeErr != nil {
				err = activeErr
			} else {
				isActive = requestedID == active.TeamInstructionsID ||
					requestedID == active.ActiveTeamInstructionsID
			}
		}
	} else {
		resp, err = client.ActiveTeamInstructions(ctx)
	}
	if err != nil {
		return err
	}

	printOutput(teamInstructionsShowOutput{
		RequestedID:      requestedID,
		IsActive:         isActive,
		TeamInstructions: resp,
	}, formatTeamInstructionsShow)
	return nil
}

func runInstructionsHistory(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.TeamInstructionsHistory(ctx, instructionsHistoryLimit)
	if err != nil {
		return err
	}
	printOutput(resp, formatTeamInstructionsHistory)
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

	active, err := client.ActiveTeamInstructions(ctx)
	if err != nil {
		return err
	}

	created, err := client.CreateTeamInstructions(ctx, &aweb.CreateTeamInstructionsRequest{
		Document: aweb.TeamInstructionsDocument{
			BodyMD: body,
			Format: "markdown",
		},
		BaseTeamInstructionsID: active.TeamInstructionsID,
	})
	if err != nil {
		return err
	}

	if _, err := client.ActivateTeamInstructions(ctx, created.TeamInstructionsID); err != nil {
		return err
	}

	printOutput(teamInstructionsSetOutput{
		TeamInstructionsID: created.TeamInstructionsID,
		Version:            created.Version,
		Activated:          true,
	}, formatTeamInstructionsSet)
	return nil
}

func runInstructionsActivate(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActivateTeamInstructions(ctx, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}

	printOutput(teamInstructionsActivateOutput{
		TeamInstructionsID: resp.ActiveTeamInstructionsID,
		Activated:          resp.Activated,
	}, formatTeamInstructionsActivate)
	return nil
}

func runInstructionsReset(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ResetTeamInstructions(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatTeamInstructionsReset)
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

func formatTeamInstructionsShow(v any) string {
	out := v.(teamInstructionsShowOutput)
	if out.TeamInstructions == nil {
		return "No active team instructions.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Team Instructions v%d", out.TeamInstructions.Version))
	if out.IsActive {
		sb.WriteString(" (active)")
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("ID: %s\n", out.TeamInstructions.TeamInstructionsID))

	body := strings.TrimSpace(out.TeamInstructions.Document.BodyMD)
	if body == "" {
		sb.WriteString("\n(empty)\n")
		return sb.String()
	}
	sb.WriteString("\n")
	sb.WriteString(body)
	sb.WriteString("\n")
	return sb.String()
}

func formatTeamInstructionsHistory(v any) string {
	out := v.(*aweb.TeamInstructionsHistoryResponse)
	if out == nil || len(out.TeamInstructionsVersions) == 0 {
		return "No team instructions versions.\n"
	}

	var sb strings.Builder
	for _, item := range out.TeamInstructionsVersions {
		status := "inactive"
		if item.IsActive {
			status = "active"
		}
		sb.WriteString(fmt.Sprintf("v%d\t%s\t%s\t%s", item.Version, status, item.CreatedAt, item.TeamInstructionsID))
		if item.CreatedByAlias != nil && strings.TrimSpace(*item.CreatedByAlias) != "" {
			sb.WriteString("\t" + strings.TrimSpace(*item.CreatedByAlias))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatTeamInstructionsSet(v any) string {
	out := v.(teamInstructionsSetOutput)
	return fmt.Sprintf("Activated team instructions v%d (%s)\n", out.Version, out.TeamInstructionsID)
}

func formatTeamInstructionsActivate(v any) string {
	out := v.(teamInstructionsActivateOutput)
	return fmt.Sprintf("Activated team instructions %s\n", out.TeamInstructionsID)
}

func formatTeamInstructionsReset(v any) string {
	out := v.(*aweb.ResetTeamInstructionsResponse)
	if out == nil {
		return "Team instructions reset.\n"
	}
	return fmt.Sprintf("Reset team instructions to default (v%d, %s)\n", out.Version, out.ActiveTeamInstructionsID)
}
