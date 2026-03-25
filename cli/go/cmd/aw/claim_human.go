package main

import (
	"context"
	"fmt"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var claimHumanEmail string

var claimHumanCmd = &cobra.Command{
	Use:   "claim-human",
	Short: "Attach a human account to your org for dashboard access",
	RunE: func(cmd *cobra.Command, args []string) error {
		if claimHumanEmail == "" {
			return usageError("missing required flag: --email")
		}

		client, err := resolveCloudClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		email := claimHumanEmail
		resp, err := client.ClaimHuman(ctx, &awid.ClaimHumanRequest{
			Email: email,
		})
		if err != nil {
			return err
		}

		printOutput(resp, formatClaimHuman)
		return nil
	},
}

func formatClaimHuman(v any) string {
	r := v.(*awid.ClaimHumanResponse)
	switch r.Status {
	case "attached":
		return fmt.Sprintf("Human account attached to %s. Dashboard access is now available.\n", r.OrgSlug)
	case "already_attached":
		return fmt.Sprintf("Human account is already attached to %s.\n", r.OrgSlug)
	default:
		return fmt.Sprintf("Verification email sent to %s. Check your inbox to complete the claim.\n", r.Email)
	}
}

func init() {
	claimHumanCmd.Flags().StringVar(&claimHumanEmail, "email", "", "Email address for human account claim")
	rootCmd.AddCommand(claimHumanCmd)
}
