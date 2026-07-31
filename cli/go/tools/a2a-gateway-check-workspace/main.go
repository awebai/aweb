// Command a2a-gateway-check-workspace creates a throwaway synthetic identity
// for validating the A2A gateway release image. It never reads an existing
// workspace and refuses to write into a non-empty directory.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const syntheticTeamID = "default:a2a-check.invalid"

func main() {
	output := flag.String("output", "", "empty directory for the synthetic workspace")
	awebURL := flag.String("aweb-url", "http://127.0.0.1:1", "non-production aweb URL recorded in the fixture")
	flag.Parse()
	if strings.TrimSpace(*output) == "" {
		fmt.Fprintln(os.Stderr, "-output is required")
		os.Exit(2)
	}
	if err := writeWorkspace(*output, *awebURL); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("synthetic A2A gateway check workspace written to %s\n", *output)
}

func writeWorkspace(root, awebURL string) error {
	root = strings.TrimSpace(root)
	if root == "" {
		return fmt.Errorf("output directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read output directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("refusing to write synthetic credentials into non-empty directory %s", root)
	}

	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generate synthetic team key: %w", err)
	}
	memberPublic, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generate synthetic member key: %w", err)
	}
	memberDID := awid.ComputeDIDKey(memberPublic)
	certificate, err := awid.SignTeamCertificate(controllerKey, awid.TeamCertificateFields{
		Team:          syntheticTeamID,
		MemberDIDKey:  memberDID,
		MemberDIDAW:   awid.ComputeStableID(memberPublic),
		MemberAddress: "a2a-check.invalid/gateway",
		Alias:         "gateway-check",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		return fmt.Errorf("sign synthetic team certificate: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o700); err != nil {
		return fmt.Errorf("create synthetic identity directory: %w", err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), memberKey); err != nil {
		return fmt.Errorf("save synthetic signing key: %w", err)
	}
	certificatePath, err := awconfig.SaveTeamCertificateForTeam(root, syntheticTeamID, certificate)
	if err != nil {
		return fmt.Errorf("save synthetic team certificate: %w", err)
	}
	workspace := &awconfig.WorktreeWorkspace{
		AwebURL: strings.TrimSpace(awebURL),
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:   syntheticTeamID,
			Alias:    "gateway-check",
			CertPath: certificatePath,
		}},
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(root, ".aw", "workspace.yaml"), workspace); err != nil {
		return fmt.Errorf("save synthetic workspace: %w", err)
	}
	teams := &awconfig.TeamState{
		ActiveTeam: syntheticTeamID,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   syntheticTeamID,
			Alias:    "gateway-check",
			CertPath: certificatePath,
			AwebURL:  strings.TrimSpace(awebURL),
		}},
	}
	if err := awconfig.SaveTeamState(root, teams); err != nil {
		return fmt.Errorf("save synthetic team state: %w", err)
	}
	return nil
}
