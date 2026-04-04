package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var identityRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate the identity signing key",
	Long:  "Generate a new Ed25519 keypair, rotate the did:key at awid.ai, and promote the local keypair.",
	RunE:  runDidRotateKey,
}

var identityLogCmd = &cobra.Command{
	Use:   "log [address]",
	Short: "Show an identity log",
	Long:  "Display rotation and status history. Without arguments, shows your own log.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDidLog,
}

var rotateKeySelfCustody bool

func init() {
	identityRotateKeyCmd.Flags().BoolVar(&rotateKeySelfCustody, "self-custody", false, "Graduate from custodial to self-custody")
	identityCmd.AddCommand(identityRotateKeyCmd)
	identityCmd.AddCommand(identityLogCmd)
}

func runDidRotateKey(cmd *cobra.Command, args []string) error {
	// Custodial graduation: no local signing key, server signs on behalf.
	if rotateKeySelfCustody {
		_, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if sel.Custody == awid.CustodySelf {
			return fmt.Errorf("identity %q is already self-custodial", sel.AccountName)
		}
		return runCustodialGraduation(sel)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	current, err := resolveCurrentIdentityContext(ctx, true)
	if err != nil {
		return err
	}
	if err := requirePermanentSelfCustodial(current); err != nil {
		return err
	}

	rotationDir, err := rotationStateDirForCurrentWorktree()
	if err != nil {
		return err
	}
	oldPriv := current.SigningKey
	registryURL, err := current.registryURL(ctx)
	if err != nil {
		return err
	}

	pending, err := loadPendingRotationState(rotationDir, current.StableID)
	if err != nil {
		return err
	}
	if pending != nil {
		return continuePendingIDRotation(ctx, current, rotationDir, registryURL, pending)
	}

	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	newDID := awid.ComputeDIDKey(newPub)
	pendingKeyPath, err := savePendingRotationKeypair(rotationDir, newDID, newPub, newPriv)
	if err != nil {
		return fmt.Errorf("save pending rotation keypair: %w", err)
	}
	pending = &pendingRotationState{
		StableID:   current.StableID,
		OldDID:     awid.ComputeDIDKey(oldPriv.Public().(ed25519.PublicKey)),
		NewDID:     newDID,
		PendingKey: pendingKeyPath,
	}
	if err := savePendingRotationState(rotationDir, pending); err != nil {
		_ = cleanupPendingRotationKeypair(pendingKeyPath)
		return err
	}
	return continuePendingIDRotation(ctx, current, rotationDir, registryURL, pending)
}

func continuePendingIDRotation(
	ctx context.Context,
	current *currentIdentityContext,
	rotationDir string,
	registryURL string,
	pending *pendingRotationState,
) error {
	if current == nil || pending == nil {
		return fmt.Errorf("missing rotation context")
	}
	activeKeyPath, err := resolveLocalSigningKeyPath(current.Selection)
	if err != nil {
		return err
	}
	newPriv, promoted, err := loadRotationSigningKey(activeKeyPath, pending)
	if err != nil {
		return err
	}
	newDID := awid.ComputeDIDKey(newPriv.Public().(ed25519.PublicKey))
	if newDID != pending.NewDID {
		return fmt.Errorf("pending rotation key does not match recorded new did:key")
	}

	resolution, err := current.Registry.ResolveKeyAt(ctx, registryURL, pending.StableID)
	if err != nil {
		return err
	}
	switch resolution.CurrentDIDKey {
	case pending.OldDID:
		oldDID := awid.ComputeDIDKey(current.SigningKey.Public().(ed25519.PublicKey))
		if oldDID != pending.OldDID {
			return fmt.Errorf("current signing key does not match pending rotation state (%s → %s)", pending.OldDID, pending.NewDID)
		}
		if _, err := current.Registry.RotateDIDKey(ctx, registryURL, pending.StableID, current.SigningKey, newPriv); err != nil {
			return err
		}
	case pending.NewDID:
		// Registry rotation already succeeded; finish local promotion.
	default:
		return fmt.Errorf("registry did:key %s does not match pending rotation state (%s → %s)", resolution.CurrentDIDKey, pending.OldDID, pending.NewDID)
	}
	return finalizeIDRotation(current, rotationDir, registryURL, pending, promoted)
}

func finalizeIDRotation(
	current *currentIdentityContext,
	rotationDir string,
	registryURL string,
	pending *pendingRotationState,
	promoted bool,
) error {
	keyPath, err := resolveLocalSigningKeyPath(current.Selection)
	if err != nil {
		return err
	}
	if !promoted {
		oldPriv := current.SigningKey
		oldDID := awid.ComputeDIDKey(oldPriv.Public().(ed25519.PublicKey))
		if oldDID != pending.OldDID {
			return fmt.Errorf("current signing key does not match pending rotation state (%s → %s)", pending.OldDID, pending.NewDID)
		}
		oldPub := oldPriv.Public().(ed25519.PublicKey)
		if err := awid.ArchiveKey(rotationDir, oldDID, oldPub, oldPriv); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to archive old key: %v\n", err)
		}
		keyPath, err = promotePendingRotationKeypair(keyPath, pending.PendingKey, pending.NewDID)
		if err != nil {
			return fmt.Errorf("activate rotated keypair: %w. Retry `aw id rotate-key` to finish local promotion", err)
		}
	} else if err := ensurePublicKeyMatchesPrivate(keyPath); err != nil {
		return fmt.Errorf("repair rotated keypair: %w. Retry `aw id rotate-key` to finish local promotion", err)
	}
	if err := updateAccountIdentity(current.Selection.AccountName, pending.NewDID, awid.CustodySelf, keyPath); err != nil {
		return fmt.Errorf("update account identity: %w. Retry `aw id rotate-key` to finish local promotion", err)
	}
	if err := removePendingRotationState(rotationDir, current.StableID); err != nil {
		return fmt.Errorf("clear pending rotation state: %w. Retry `aw id rotate-key` to finish local promotion", err)
	}

	printOutput(idRotateOutput{
		Status:      "rotated",
		RegistryURL: registryURL,
		OldDID:      pending.OldDID,
		NewDID:      pending.NewDID,
	}, formatIDRotate)
	return nil
}

// runCustodialGraduation handles the --self-custody path for custodial agents.
// The server holds the old key and signs the rotation on behalf.
func runCustodialGraduation(sel *awconfig.Selection) error {
	// Generate new keypair locally.
	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	newDID := awid.ComputeDIDKey(newPub)

	// Use a regular API-key client (no local signing key).
	c, err := aweb.NewWithAPIKey(sel.BaseURL, sel.APIKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// PUT with no rotation_signature — server signs on behalf.
	resp, err := c.RotateKeyCustodial(ctx, &awid.RotateKeyCustodialRequest{
		NewDID:       newDID,
		NewPublicKey: newPub,
		Custody:      awid.CustodySelf,
	})
	if err != nil {
		return err
	}

	// Save the new keypair at the worktree-local signing-key path.
	keyPath, err := resolveLocalSigningKeyPath(sel)
	if err != nil {
		return err
	}
	if err := awid.SaveKeypairAt(keyPath, awid.PublicKeyPath(keyPath), newPub, newPriv); err != nil {
		return fmt.Errorf("save new keypair: %w", err)
	}

	// Update config.
	if err := updateAccountIdentity(sel.AccountName, newDID, awid.CustodySelf, keyPath); err != nil {
		return err
	}
	printOutput(idRotateOutput{
		Status: "graduated",
		OldDID: resp.OldDID,
		NewDID: resp.NewDID,
	}, formatIDRotate)

	return nil
}

func runDidLog(cmd *cobra.Command, args []string) error {
	c, err := resolveClient()
	if err != nil {
		return err
	}

	var address string
	if len(args) > 0 {
		address = args[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.AgentLog(ctx, address)
	if err != nil {
		return err
	}

	if len(resp.Entries) == 0 {
		fmt.Println("No log entries.")
		return nil
	}

	for _, e := range resp.Entries {
		fmt.Printf("[%s] %s\n", e.Timestamp, e.Operation)
		if e.DID != "" {
			fmt.Printf("  did: %s\n", e.DID)
		}
		if e.OldDID != "" {
			fmt.Printf("  old_did: %s\n", e.OldDID)
		}
		if e.NewDID != "" {
			fmt.Printf("  new_did: %s\n", e.NewDID)
		}
		if e.SignedBy != "" {
			fmt.Printf("  signed_by: %s\n", e.SignedBy)
		}
	}

	return nil
}

func resolveLocalSigningKeyPath(sel *awconfig.Selection) (string, error) {
	if sel != nil && strings.TrimSpace(sel.SigningKey) != "" {
		return strings.TrimSpace(sel.SigningKey), nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return awconfig.WorktreeSigningKeyPath(wd), nil
}

func resolveCurrentAccountName(accountName string) (string, error) {
	if strings.TrimSpace(accountName) != "" {
		return strings.TrimSpace(accountName), nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	cfg, err := awconfig.LoadGlobal()
	if err != nil {
		return "", err
	}
	var ctx *awconfig.WorktreeContext
	if loaded, _, loadErr := awconfig.LoadWorktreeContextFromDir(wd); loadErr == nil {
		ctx = loaded
	} else if !os.IsNotExist(loadErr) {
		return "", loadErr
	}
	sel, err := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		ClientName: "aw",
		Context:    ctx,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(sel.AccountName), nil
}

// updateAccountIdentity updates DID, custody, and signing key path in the global config.
func updateAccountIdentity(accountName, newDID, custody, signingKeyPath string) error {
	resolvedAccountName, err := resolveCurrentAccountName(accountName)
	if err != nil {
		return err
	}

	configPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	if err := awconfig.UpdateGlobalAt(configPath, func(cfg *awconfig.GlobalConfig) error {
		acct := cfg.Accounts[resolvedAccountName]
		acct.DID = newDID
		acct.Custody = custody
		acct.SigningKey = signingKeyPath
		cfg.Accounts[resolvedAccountName] = acct
		return nil
	}); err != nil {
		return err
	}

	if wd, wdErr := os.Getwd(); wdErr == nil {
		workspacePath := filepath.Join(wd, awconfig.DefaultWorktreeWorkspaceRelativePath())
		identityPath := filepath.Join(wd, awconfig.DefaultWorktreeIdentityRelativePath())
		hasPersistentIdentity := false
		if _, statErr := os.Stat(identityPath); statErr == nil {
			hasPersistentIdentity = true
		} else if !os.IsNotExist(statErr) {
			return statErr
		}

		if workspace, loadErr := awconfig.LoadWorktreeWorkspaceFrom(workspacePath); loadErr == nil && !hasPersistentIdentity {
			workspace.DID = newDID
			workspace.Custody = custody
			workspace.SigningKey = signingKeyPath
			if saveErr := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); saveErr != nil {
				return saveErr
			}
		} else if loadErr != nil && !os.IsNotExist(loadErr) {
			return loadErr
		}

		if identity, loadErr := awconfig.LoadWorktreeIdentityFrom(identityPath); loadErr == nil {
			identity.DID = newDID
			identity.Custody = custody
			if saveErr := awconfig.SaveWorktreeIdentityTo(identityPath, identity); saveErr != nil {
				return saveErr
			}
		} else if !os.IsNotExist(loadErr) {
			return loadErr
		}
	}
	return nil
}
