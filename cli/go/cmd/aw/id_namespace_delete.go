package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

type idNamespaceDeleteOutput struct {
	Status          string   `json:"status"`
	Domain          string   `json:"domain"`
	ControllerDID   string   `json:"controller_did"`
	RegistryURL     string   `json:"registry_url"`
	LocalBackupDir  string   `json:"local_backup_dir,omitempty"`
	MovedLocalPaths []string `json:"moved_local_paths,omitempty"`
}

type idNamespaceDeleteOptions struct {
	Domain      string
	RegistryURL string
	Reason      string
	PurgeLocal  bool
}

var (
	idNamespaceDeleteDomain     string
	idNamespaceDeleteRegistry   string
	idNamespaceDeleteReason     string
	idNamespaceDeletePurgeLocal bool
	idNamespaceDeleteCmd        = &cobra.Command{
		Use:   "delete",
		Short: "Delete an AWID namespace using the local controller key",
		Long: "Delete an AWID namespace using the local namespace controller key.\n\n" +
			"Namespace deletion requires all active certificates in the namespace to be\n" +
			"revoked first. It does not update DNS; remove any _awid TXT record at your\n" +
			"DNS provider after the registry delete succeeds. Local controller/team key\n" +
			"files are preserved unless --purge-local is set, in which case they are moved\n" +
			"to ~/.awid/deregister-backups/ instead of being unlinked.",
		RunE: runIDNamespaceDelete,
	}
)

func init() {
	idNamespaceDeleteCmd.Flags().StringVar(&idNamespaceDeleteDomain, "domain", "", "Namespace domain (e.g. aweb.ai)")
	idNamespaceDeleteCmd.Flags().StringVar(&idNamespaceDeleteRegistry, "registry", "", "Registry origin override")
	idNamespaceDeleteCmd.Flags().StringVar(&idNamespaceDeleteReason, "reason", "", "Optional deletion reason recorded by the registry")
	idNamespaceDeleteCmd.Flags().BoolVar(&idNamespaceDeletePurgeLocal, "purge-local", false, "Move local controller and team keys for the namespace to ~/.awid/deregister-backups after successful registry delete")
	idNamespaceCmd.AddCommand(idNamespaceDeleteCmd)
}

func runIDNamespaceDelete(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := executeIDNamespaceDelete(ctx, idNamespaceDeleteOptions{
		Domain:      idNamespaceDeleteDomain,
		RegistryURL: idNamespaceDeleteRegistry,
		Reason:      idNamespaceDeleteReason,
		PurgeLocal:  idNamespaceDeletePurgeLocal,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDNamespaceDelete)
	return nil
}

func executeIDNamespaceDelete(ctx context.Context, opts idNamespaceDeleteOptions) (idNamespaceDeleteOutput, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return idNamespaceDeleteOutput{}, err
	}
	controllerKey, controllerDID, err := loadVerifiedNamespaceControllerKey(ctx, domain, opts.RegistryURL)
	if err != nil {
		return idNamespaceDeleteOutput{}, err
	}

	registry, err := newRegistryClientWithPreferredBaseURL(opts.RegistryURL)
	if err != nil {
		return idNamespaceDeleteOutput{}, err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return idNamespaceDeleteOutput{}, fmt.Errorf("discover registry for %s: %w", domain, err)
	}

	if err := registry.DeleteNamespaceAt(ctx, registryURL, domain, controllerKey, opts.Reason); err != nil {
		if code, ok := registryStatusCode(err); ok && code == http.StatusConflict {
			return idNamespaceDeleteOutput{}, fmt.Errorf("delete namespace %s: active certificates exist; run `aw id team remove-member` for active members first: %w", domain, err)
		}
		return idNamespaceDeleteOutput{}, fmt.Errorf("delete namespace %s: %w", domain, err)
	}

	out := idNamespaceDeleteOutput{
		Status:        "deleted",
		Domain:        domain,
		ControllerDID: controllerDID,
		RegistryURL:   registryURL,
	}
	if opts.PurgeLocal {
		backupDir, moved, err := moveNamespaceLocalState(domain)
		if err != nil {
			return idNamespaceDeleteOutput{}, err
		}
		out.LocalBackupDir = backupDir
		out.MovedLocalPaths = moved
	}
	return out, nil
}

func moveNamespaceLocalState(domain string) (string, []string, error) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	safeDomain := strings.ReplaceAll(domain, string(filepath.Separator), "_")
	backupDir, err := awconfig.PathInAWIDState("deregister-backups", safeDomain+"-"+stamp)
	if err != nil {
		return "", nil, err
	}
	var moved []string

	controllerKeyPath, err := awconfig.ControllerKeyPath(domain)
	if err != nil {
		return "", nil, err
	}
	controllerMetaPath, err := awconfig.ControllerMetaPath(domain)
	if err != nil {
		return "", nil, err
	}
	teamKeysRoot, err := awconfig.DefaultTeamKeysDir()
	if err != nil {
		return "", nil, err
	}
	teamKeysDir := filepath.Join(teamKeysRoot, domain)

	for _, path := range []string{controllerKeyPath, controllerMetaPath, teamKeysDir} {
		exists, err := pathExists(path)
		if err != nil {
			return "", nil, err
		}
		if !exists {
			continue
		}
		if err := os.MkdirAll(backupDir, 0o700); err != nil {
			return "", nil, err
		}
		dst := filepath.Join(backupDir, filepath.Base(path))
		if path == teamKeysDir {
			dst = filepath.Join(backupDir, "team-keys")
		}
		if err := os.Rename(path, dst); err != nil {
			return "", nil, fmt.Errorf("move %s to %s: %w", path, dst, err)
		}
		moved = append(moved, dst)
	}
	if len(moved) == 0 {
		return "", nil, nil
	}
	return backupDir, moved, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func formatIDNamespaceDelete(v any) string {
	out := v.(idNamespaceDeleteOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Deleted namespace %s\n", out.Domain)
	fmt.Fprintf(&b, "  controller:    %s\n", out.ControllerDID)
	fmt.Fprintf(&b, "  registry:      %s\n", out.RegistryURL)
	if out.LocalBackupDir != "" {
		fmt.Fprintf(&b, "  local backup:  %s\n", out.LocalBackupDir)
	}
	return b.String()
}
