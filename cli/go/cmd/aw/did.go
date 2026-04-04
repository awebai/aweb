package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
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
	Long:  "Generate a new Ed25519 keypair, sign the rotation with the old key, and update the server and local config.",
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

	keysDir, err := keysDirForCurrentConfig()
	if err != nil {
		return err
	}
	oldPriv := current.SigningKey
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	oldDID := current.DID
	registryURL, err := current.registryURL(ctx)
	if err != nil {
		return err
	}

	if pending, err := loadPendingRotationState(keysDir, current.StableID); err != nil {
		return err
	} else if pending != nil {
		return continuePendingIDRotation(ctx, current, keysDir, oldPriv, oldPub, oldDID, pending)
	}

	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	newDID := awid.ComputeDIDKey(newPub)
	pendingKeyPath, err := savePendingRotationKeypair(keysDir, newDID, newPub, newPriv)
	if err != nil {
		return fmt.Errorf("save pending rotation keypair: %w", err)
	}
	pending := &pendingRotationState{
		StableID:    current.StableID,
		Address:     current.Address,
		OldDID:      oldDID,
		NewDID:      newDID,
		RegistryURL: registryURL,
		PendingKey:  pendingKeyPath,
	}
	if err := savePendingRotationState(keysDir, pending); err != nil {
		_ = cleanupPendingRotationKeypair(pendingKeyPath)
		return err
	}
	if _, err := current.Registry.RotateDIDKey(ctx, registryURL, current.StableID, oldPriv, newPriv); err != nil {
		_ = removePendingRotationState(keysDir, current.StableID)
		_ = cleanupPendingRotationKeypair(pendingKeyPath)
		return err
	}
	return continuePendingIDRotation(ctx, current, keysDir, oldPriv, oldPub, oldDID, pending)
}

func continuePendingIDRotation(
	ctx context.Context,
	current *currentIdentityContext,
	keysDir string,
	oldPriv ed25519.PrivateKey,
	oldPub ed25519.PublicKey,
	oldDID string,
	pending *pendingRotationState,
) error {
	if current == nil || pending == nil {
		return fmt.Errorf("missing rotation context")
	}
	newPriv, err := awid.LoadSigningKey(pending.PendingKey)
	if err != nil {
		return fmt.Errorf("load pending rotation key: %w", err)
	}
	newPub := newPriv.Public().(ed25519.PublicKey)
	newDID := awid.ComputeDIDKey(newPub)
	if strings.TrimSpace(newDID) != strings.TrimSpace(pending.NewDID) {
		return fmt.Errorf("pending rotation key does not match recorded new did:key")
	}
	if strings.TrimSpace(current.DID) == strings.TrimSpace(newDID) {
		return finalizeIDRotation(current, keysDir, oldPriv, oldPub, oldDID, pending, "synced")
	}
	if strings.TrimSpace(current.DID) != strings.TrimSpace(pending.OldDID) {
		return fmt.Errorf("current did:key %s does not match pending rotation state (%s → %s)", current.DID, pending.OldDID, pending.NewDID)
	}

	resp, err := current.Client.RotateKey(ctx, &awid.RotateKeyRequest{
		NewDID:       newDID,
		NewPublicKey: newPub,
		Custody:      awid.CustodySelf,
	})
	if err != nil {
		warning := fmt.Sprintf("registry rotation succeeded, but the server update failed: %v. Retry `aw id rotate-key` to finish syncing the server.", err)
		fmt.Fprintln(os.Stderr, "Warning:", warning)
		printOutput(idRotateOutput{
			Status:       "pending_server_update",
			RegistryURL:  pending.RegistryURL,
			OldDID:       pending.OldDID,
			NewDID:       pending.NewDID,
			Warning:      warning,
			PendingRetry: true,
		}, formatIDRotate)
		return nil
	}
	_ = resp
	return finalizeIDRotation(current, keysDir, oldPriv, oldPub, oldDID, pending, "rotated")
}

func finalizeIDRotation(
	current *currentIdentityContext,
	keysDir string,
	oldPriv ed25519.PrivateKey,
	oldPub ed25519.PublicKey,
	oldDID string,
	pending *pendingRotationState,
	status string,
) error {
	if err := awid.ArchiveKey(keysDir, oldDID, oldPub, oldPriv); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to archive old key: %v\n", err)
	}
	keyPath, err := promotePendingRotationKeypair(keysDir, current.Address, pending.PendingKey)
	if err != nil {
		return fmt.Errorf("activate rotated keypair: %w", err)
	}
	if err := updateAccountIdentity(current.Selection.AccountName, pending.NewDID, awid.CustodySelf, keyPath); err != nil {
		return err
	}
	if err := removePendingRotationState(keysDir, current.StableID); err != nil {
		return err
	}

	printOutput(idRotateOutput{
		Status:      status,
		RegistryURL: pending.RegistryURL,
		OldDID:      oldDID,
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

	// Save new keypair.
	configPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	keysDir := awconfig.KeysDir(configPath)
	address := deriveIdentityAddress(sel.NamespaceSlug, sel.DefaultProject, sel.IdentityHandle)
	if err := awid.SaveKeypair(keysDir, address, newPub, newPriv); err != nil {
		return fmt.Errorf("save new keypair: %w", err)
	}

	// Update config.
	keyPath := awid.SigningKeyPath(keysDir, address)
	if err := updateAccountIdentity(sel.AccountName, newDID, awid.CustodySelf, keyPath); err != nil {
		return err
	}

	fmt.Printf("Graduated to self-custody.\n")
	fmt.Printf("  old DID: %s\n", resp.OldDID)
	fmt.Printf("  new DID: %s\n", resp.NewDID)

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

// updateAccountIdentity updates DID, custody, and signing key path in the global config.
func updateAccountIdentity(accountName, newDID, custody, signingKeyPath string) error {
	configPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	return awconfig.UpdateGlobalAt(configPath, func(cfg *awconfig.GlobalConfig) error {
		acct := cfg.Accounts[accountName]
		acct.DID = newDID
		acct.Custody = custody
		acct.SigningKey = signingKeyPath
		cfg.Accounts[accountName] = acct
		return nil
	})
}
