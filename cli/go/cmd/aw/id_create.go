package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idCreateOutput struct {
	Status         string `json:"status"`
	DIDAW          string `json:"did_aw"`
	DIDKey         string `json:"did_key"`
	IdentityPath   string `json:"identity_path"`
	SigningKeyPath string `json:"signing_key_path"`
	RegistryStatus string `json:"registry_status"`
	RegistryURL    string `json:"registry_url,omitempty"`
	RegistryError  string `json:"registry_error,omitempty"`
}

var (
	idCreateName string
	idCreateCmd  = &cobra.Command{
		Use:   "create",
		Short: "Create a standalone permanent identity in .aw/",
		RunE:  runIDCreate,
	}
)

func init() {
	idCreateCmd.Flags().StringVar(&idCreateName, "name", "", "Permanent identity name")
	identityCmd.AddCommand(idCreateCmd)
}

func runIDCreate(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(idCreateName) == "" {
		return usageError("--name is required")
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	signingKeyPath := filepath.Join(workingDir, ".aw", "signing.key")
	workspacePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())

	if err := ensureStandaloneIdentityTarget(identityPath, signingKeyPath, workspacePath); err != nil {
		return err
	}

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	didKey := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL := strings.TrimSpace(registry.DefaultRegistryURL)
	registryStatus := "registered"
	registryErr := ""
	if _, err := registry.RegisterDID(ctx, registryURL, "", "", "", didKey, stableID, priv); err != nil {
		if !isRegistryUnavailableError(err) {
			return err
		}
		registryStatus = "unreachable"
		registryErr = err.Error()
		warnWriter := cmd.ErrOrStderr()
		if warnWriter == nil {
			warnWriter = os.Stderr
		}
		fmt.Fprintf(warnWriter, "Warning: could not register identity at awid.ai: %v\n", err)
	}

	if err := awconfig.SaveWorktreeIdentityTo(identityPath, &awconfig.WorktreeIdentity{
		DID:       didKey,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return err
	}
	if err := awid.SaveSigningKey(signingKeyPath, priv); err != nil {
		return err
	}

	printOutput(idCreateOutput{
		Status:         "created",
		DIDAW:          stableID,
		DIDKey:         didKey,
		IdentityPath:   identityPath,
		SigningKeyPath: signingKeyPath,
		RegistryStatus: registryStatus,
		RegistryURL:    registryURL,
		RegistryError:  registryErr,
	}, formatIDCreate)
	return nil
}

func ensureStandaloneIdentityTarget(identityPath, signingKeyPath, workspacePath string) error {
	if _, err := os.Stat(identityPath); err == nil {
		return usageError("standalone identity already exists at %s", identityPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(workspacePath); err == nil {
		return usageError("current directory already has a workspace at %s; use a clean directory for `aw id create`", workspacePath)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(signingKeyPath); err == nil {
		return usageError("refusing to overwrite existing signing key at %s", signingKeyPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func isRegistryUnavailableError(err error) bool {
	var regErr *awid.RegistryError
	if errors.As(err, &regErr) {
		return regErr.StatusCode >= 500
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}
