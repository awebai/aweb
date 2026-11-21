package main

import (
	"errors"
	"fmt"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type validationKind string

const (
	validationAlias         validationKind = "alias"
	validationTeamID        validationKind = "team-id"
	validationTeamServerURL validationKind = "team-server-url"
)

type validationOutput struct {
	Kind      validationKind `json:"kind"`
	Input     string         `json:"input"`
	Valid     bool           `json:"valid"`
	Canonical string         `json:"canonical"`
	Audience  string         `json:"audience,omitempty"`
}

var validateCmd = &cobra.Command{Use: "validate", Short: "Query the CLI's identifier and URL rules without identity or network access", GroupID: groupUtility}
var validateAliasCmd = &cobra.Command{Use: "alias <name>", Short: "Check a workspace alias using the CLI's alias rule", Args: cobra.ExactArgs(1), RunE: runValidateAlias}
var validateTeamIDCmd = &cobra.Command{Use: "team-id <name:domain>", Short: "Parse and normalize a team ID using the SDK's input rule", Args: cobra.ExactArgs(1), RunE: runValidateTeamID}
var validateTeamServerURLCmd = &cobra.Command{Use: "team-server-url <url>", Short: "Query canonical team-server URL and audience spelling", Args: cobra.ExactArgs(1), RunE: runValidateTeamServerURL}

func runValidateAlias(cmd *cobra.Command, args []string) error {
	canonical, err := normalizeIDCreateName(args[0])
	out := validationOutput{Kind: validationAlias, Input: args[0], Valid: err == nil, Canonical: canonical}
	outputErr := printJSON(out)
	if err != nil {
		return errors.Join(withErrorCode("invalid_alias", fmt.Errorf("%w. Use a nonempty enrollment alias without '/' and retry.", err)), outputErr)
	}
	return outputErr
}

func runValidateTeamID(cmd *cobra.Command, args []string) error {
	domain, name, err := awid.ParseTeamID(args[0])
	out := validationOutput{Kind: validationTeamID, Input: args[0], Valid: err == nil, Canonical: awid.BuildTeamID(domain, name)}
	outputErr := printJSON(out)
	if err != nil {
		return errors.Join(withErrorCode("invalid_team_id", fmt.Errorf("%w. Use a team ID in name:domain form.", err)), outputErr)
	}
	return outputErr
}

func runValidateTeamServerURL(cmd *cobra.Command, args []string) error {
	canonical, audience, err := awid.CanonicalTeamServerURL(args[0])
	out := validationOutput{Kind: validationTeamServerURL, Input: args[0], Valid: err == nil, Canonical: canonical, Audience: audience}
	outputErr := printJSON(out)
	if err != nil {
		return errors.Join(withErrorCode("invalid_team_server_url", fmt.Errorf("%w. Use an HTTPS team server URL, or an allowed loopback URL for local use.", err)), outputErr)
	}
	return outputErr
}

func init() {
	for _, cmd := range []*cobra.Command{validateAliasCmd, validateTeamIDCmd, validateTeamServerURLCmd} {
		offlineCommands[cmd] = struct{}{}
		identityHomeNeutralCommandExemptions[cmd] = struct{}{}
		validateCmd.AddCommand(cmd)
	}
	rootCmd.AddCommand(validateCmd)
}
