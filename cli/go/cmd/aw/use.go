package main

import (
	"fmt"
	"os"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var useCmd = &cobra.Command{
	Use:   "use <account-or-alias>",
	Short: "Use an existing identity in this workspace",
	Args:  cobra.ExactArgs(1),
	RunE:  runUse,
}

type useOutput struct {
	Account       string `json:"account"`
	Server        string `json:"server"`
	Alias         string `json:"alias,omitempty"`
	Project       string `json:"project,omitempty"`
	IdentityClass string `json:"identity_class,omitempty"`
	ContextStatus string `json:"context_status,omitempty"`
}

func init() {
	rootCmd.AddCommand(useCmd)
}

func runUse(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}

	sel, err := resolveNamedSelectionForDir(workingDir, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}
	if strings.TrimSpace(sel.AccountName) == "" {
		return usageError("use requires a configured aw identity; run 'aw init', 'aw project create', or 'aw connect' first")
	}
	if strings.TrimSpace(sel.ServerName) == "" {
		return usageError("use requires a configured aw server; run 'aw init', 'aw project create', or 'aw connect' first")
	}

	if err := writeOrUpdateContext(sel.ServerName, sel.AccountName); err != nil {
		return err
	}

	baseURL, err := resolveAuthenticatedBaseURL(sel.BaseURL)
	if err != nil {
		return err
	}
	client, err := aweb.NewWithAPIKey(baseURL, sel.APIKey)
	if err != nil {
		return err
	}
	configureBaseURLFallback(client, sel, baseURL)
	attachResult, err := autoAttachContext(workingDir, client, "")
	if err != nil {
		return err
	}
	if err := persistWorkspaceBinding(workspaceBindingInput{
		WorkingDir:     workingDir,
		ServerURL:      baseURL,
		APIKey:         sel.APIKey,
		ProjectSlug:    sel.DefaultProject,
		NamespaceSlug:  sel.NamespaceSlug,
		IdentityID:     sel.IdentityID,
		IdentityHandle: sel.IdentityHandle,
		DID:            sel.DID,
		StableID:       sel.StableID,
		SigningKey:     sel.SigningKey,
		Custody:        sel.Custody,
		Lifetime:       sel.Lifetime,
		AttachResult:   attachResult,
	}); err != nil {
		return err
	}

	contextStatus := "none"
	if attachResult != nil {
		switch strings.TrimSpace(attachResult.ContextKind) {
		case "repo_worktree":
			if attachResult.Workspace != nil {
				contextStatus = "attached " + strings.TrimSpace(attachResult.Workspace.CanonicalOrigin)
			}
		case "local_dir":
			contextStatus = "attached local directory"
		}
	}

	printOutput(useOutput{
		Account:       sel.AccountName,
		Server:        sel.ServerName,
		Alias:         sel.IdentityHandle,
		Project:       sel.NamespaceSlug,
		IdentityClass: awid.DescribeIdentityClass(sel.Lifetime),
		ContextStatus: contextStatus,
	}, formatUse)
	return nil
}

func resolveNamedSelectionForDir(workingDir, target string) (*awconfig.Selection, error) {
	cfg, err := awconfig.LoadGlobal()
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	sel, err := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		ServerName:        serverFlag,
		AccountName:       strings.TrimSpace(target),
		ClientName:        "aw",
		WorkingDir:        workingDir,
		AllowEnvOverrides: true,
	})
	if err != nil {
		return nil, err
	}
	return sel, nil
}

func formatUse(v any) string {
	out := v.(useOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Using identity %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Account:    %s\n", out.Account))
	sb.WriteString(fmt.Sprintf("Server:     %s\n", out.Server))
	if strings.TrimSpace(out.Project) != "" {
		sb.WriteString(fmt.Sprintf("Project:    %s\n", out.Project))
	}
	if strings.TrimSpace(out.IdentityClass) != "" {
		sb.WriteString(fmt.Sprintf("Identity:   %s\n", out.IdentityClass))
	}
	if strings.TrimSpace(out.ContextStatus) != "" {
		sb.WriteString(fmt.Sprintf("Context:    %s\n", out.ContextStatus))
	}
	return sb.String()
}
