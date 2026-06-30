package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idEncryptionKeyOutput struct {
	Status         string   `json:"status"`
	KeyID          string   `json:"key_id,omitempty"`
	PublicKey      string   `json:"public_key,omitempty"`
	PrivateKey     string   `json:"private_key_path,omitempty"`
	StatePath      string   `json:"state_path,omitempty"`
	AssertionPath  string   `json:"assertion_path,omitempty"`
	Published      []string `json:"published,omitempty"`
	PublishSkipped []string `json:"publish_skipped,omitempty"`
	Warning        string   `json:"warning,omitempty"`
}

var idEncryptionKeyCmd = &cobra.Command{
	Use:   "encryption-key",
	Short: "Manage local E2E encryption keys for this self-custodial identity",
}

var idEncryptionKeySetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Create or publish the local E2E encryption key for this identity",
	RunE:  runIDEncryptionKeySetup,
}

var idEncryptionKeyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the local E2E encryption key while keeping archived keys",
	RunE:  runIDEncryptionKeyRotate,
}

var idEncryptionKeyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show local E2E encryption key state",
	RunE:  runIDEncryptionKeyShow,
}

func init() {
	idEncryptionKeyCmd.AddCommand(idEncryptionKeySetupCmd)
	idEncryptionKeyCmd.AddCommand(idEncryptionKeyRotateCmd)
	idEncryptionKeyCmd.AddCommand(idEncryptionKeyShowCmd)
	identityCmd.AddCommand(idEncryptionKeyCmd)
}

func runIDEncryptionKeySetup(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := setupOrRotateIdentityEncryptionKey(ctx, false)
	if err != nil {
		return err
	}
	printOutput(out, formatIDEncryptionKey)
	return nil
}

func runIDEncryptionKeyRotate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := setupOrRotateIdentityEncryptionKey(ctx, true)
	if err != nil {
		return err
	}
	printOutput(out, formatIDEncryptionKey)
	return nil
}

func runIDEncryptionKeyShow(cmd *cobra.Command, args []string) error {
	identity, err := resolveIdentity()
	if err != nil {
		return err
	}
	statePath := awconfig.WorktreeEncryptionStatePath(identity.WorkingDir)
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return usageError("no local E2E encryption key state found; run `aw id encryption-key setup`")
		}
		return err
	}
	record := state.ActiveRecord()
	if record == nil {
		return usageError("local E2E encryption key state has no active key; run `aw id encryption-key setup`")
	}
	printOutput(idEncryptionKeyOutput{
		Status:        "present",
		KeyID:         record.KeyID,
		PublicKey:     record.PublicKey,
		PrivateKey:    resolveWorktreeRelativePath(identity.WorkingDir, record.PrivateKeyPath),
		StatePath:     statePath,
		AssertionPath: resolveWorktreeRelativePath(identity.WorkingDir, record.AssertionPath),
		Warning:       encryptionKeyBackupWarning(),
	}, formatIDEncryptionKey)
	return nil
}

func setupOrRotateIdentityEncryptionKey(ctx context.Context, rotate bool) (idEncryptionKeyOutput, error) {
	wd, _ := os.Getwd()
	return setupOrRotateIdentityEncryptionKeyForDir(ctx, wd, rotate)
}

func setupOrRotateIdentityEncryptionKeyForDir(ctx context.Context, workingDir string, rotate bool) (idEncryptionKeyOutput, error) {
	identity, err := resolveIdentityForEncryptionKeyForDir(workingDir)
	if err != nil {
		return idEncryptionKeyOutput{}, err
	}
	signingKey, err := resolveIdentitySigningKey(identity)
	if err != nil {
		return idEncryptionKeyOutput{}, err
	}
	if strings.TrimSpace(identity.Custody) != awid.CustodySelf {
		return idEncryptionKeyOutput{}, usageError("E2E encryption keys are local self-custodial keys; this identity custody is %q", strings.TrimSpace(identity.Custody))
	}
	if got := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); got != strings.TrimSpace(identity.DID) {
		return idEncryptionKeyOutput{}, usageError("current identity is invalid: .aw/identity.yaml did %q does not match .aw/signing.key %q", strings.TrimSpace(identity.DID), got)
	}

	statePath := awconfig.WorktreeEncryptionStatePath(identity.WorkingDir)
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			state = &awconfig.EncryptionKeyState{}
		} else {
			return idEncryptionKeyOutput{}, err
		}
	}

	previousKeyID := ""
	if active := state.ActiveRecord(); active != nil {
		previousKeyID = active.KeyID
	}
	if rotate && strings.TrimSpace(previousKeyID) == "" {
		return idEncryptionKeyOutput{}, usageError("no active E2E encryption key found; run `aw id encryption-key setup` first")
	}

	record := state.ActiveRecord()
	assertion := (*awid.EncryptionKeyAssertion)(nil)
	status := "published"
	if record == nil || rotate {
		record, assertion, err = createLocalEncryptionKeyRecord(identity, signingKey, previousKeyID)
		if err != nil {
			return idEncryptionKeyOutput{}, err
		}
		state.ActiveKeyID = record.KeyID
		state.UpsertRecord(*record)
		if err := awconfig.SaveEncryptionKeyStateTo(statePath, state); err != nil {
			return idEncryptionKeyOutput{}, err
		}
		status = "created"
		if rotate {
			status = "rotated"
		}
	} else {
		material, err := validateEncryptionRecordPrivateKey(identity.WorkingDir, record)
		if err != nil {
			return idEncryptionKeyOutput{}, err
		}
		assertion, err = loadEncryptionAssertion(identity.WorkingDir, record.AssertionPath)
		if err != nil {
			return idEncryptionKeyOutput{}, err
		}
		if err := validateEncryptionRecordAssertion(identity, record, assertion, material); err != nil {
			if !shouldRefreshEncryptionKeyForIdentityBinding(err) {
				return idEncryptionKeyOutput{}, err
			}
			record, assertion, err = createLocalEncryptionKeyRecord(identity, signingKey, record.KeyID)
			if err != nil {
				return idEncryptionKeyOutput{}, err
			}
			state.ActiveKeyID = record.KeyID
			state.UpsertRecord(*record)
			if err := awconfig.SaveEncryptionKeyStateTo(statePath, state); err != nil {
				return idEncryptionKeyOutput{}, err
			}
			status = "rotated"
		}
	}

	published, skipped, publishErr := publishIdentityEncryptionKey(ctx, identity, signingKey, assertion)
	if publishErr != nil {
		return idEncryptionKeyOutput{}, publishErr
	}
	if len(published) > 0 {
		record.PublishedAt = time.Now().UTC().Format(time.RFC3339)
		state.UpsertRecord(*record)
		_ = awconfig.SaveEncryptionKeyStateTo(statePath, state)
	}

	return idEncryptionKeyOutput{
		Status:         status,
		KeyID:          record.KeyID,
		PublicKey:      record.PublicKey,
		PrivateKey:     resolveWorktreeRelativePath(identity.WorkingDir, record.PrivateKeyPath),
		StatePath:      statePath,
		AssertionPath:  resolveWorktreeRelativePath(identity.WorkingDir, record.AssertionPath),
		Published:      published,
		PublishSkipped: skipped,
		Warning:        encryptionKeyBackupWarning(),
	}, nil
}

func ensureLocalIdentityEncryptionKeyForDir(workingDir string) error {
	identity, err := resolveIdentityForEncryptionKeyForDir(workingDir)
	if err != nil {
		return err
	}
	signingKey, err := resolveIdentitySigningKey(identity)
	if err != nil {
		return err
	}
	if strings.TrimSpace(identity.Custody) != awid.CustodySelf {
		return nil
	}
	if got := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); got != strings.TrimSpace(identity.DID) {
		return usageError("current identity is invalid: .aw/identity.yaml did %q does not match .aw/signing.key %q", strings.TrimSpace(identity.DID), got)
	}

	statePath := awconfig.WorktreeEncryptionStatePath(identity.WorkingDir)
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			state = &awconfig.EncryptionKeyState{}
		} else {
			return err
		}
	}
	if record := state.ActiveRecord(); record != nil {
		material, err := validateEncryptionRecordPrivateKey(identity.WorkingDir, record)
		if err != nil {
			return err
		}
		assertion, err := loadEncryptionAssertion(identity.WorkingDir, record.AssertionPath)
		if err != nil {
			return err
		}
		if err := validateEncryptionRecordAssertion(identity, record, assertion, material); err != nil {
			if !shouldRefreshEncryptionKeyForIdentityBinding(err) {
				return err
			}
			next, _, err := createLocalEncryptionKeyRecord(identity, signingKey, record.KeyID)
			if err != nil {
				return err
			}
			state.ActiveKeyID = next.KeyID
			state.UpsertRecord(*next)
			return awconfig.SaveEncryptionKeyStateTo(statePath, state)
		}
		return nil
	}

	record, _, err := createLocalEncryptionKeyRecord(identity, signingKey, "")
	if err != nil {
		return err
	}
	state.ActiveKeyID = record.KeyID
	state.UpsertRecord(*record)
	return awconfig.SaveEncryptionKeyStateTo(statePath, state)
}

func shouldRefreshEncryptionKeyForIdentityBinding(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "identity_stable_id") ||
		strings.Contains(msg, "identity_did does not match current did:key")
}

func resolveIdentityForEncryptionKeyForDir(workingDir string) (*awconfig.ResolvedIdentity, error) {
	if certIdentity, err := resolveActiveCertificateIdentityForEncryptionKey(workingDir); err != nil {
		return nil, err
	} else if certIdentity != nil {
		return certIdentity, nil
	}

	identity, err := awconfig.ResolveIdentity(workingDir)
	if err == nil {
		if err := validateResolvedIdentity(identity); err != nil {
			return nil, err
		}
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, usageError("current identity has no local signing key")
		}
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))

	return &awconfig.ResolvedIdentity{
		WorkingDir:     strings.TrimSpace(workingDir),
		SigningKeyPath: signingKeyPath,
		DID:            didKey,
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeLocal,
		Lifetime:       awid.LifetimeEphemeral,
	}, nil
}

func resolveActiveCertificateIdentityForEncryptionKey(workingDir string) (*awconfig.ResolvedIdentity, error) {
	var cert *awid.TeamCertificate
	registryURL := ""
	if teamState, err := awconfig.LoadTeamState(workingDir); err == nil && teamState != nil {
		if active := strings.TrimSpace(teamState.ActiveTeam); active != "" {
			if membership := teamState.Membership(active); membership != nil {
				registryURL = strings.TrimSpace(membership.RegistryURL)
			}
			cert, _ = awconfig.LoadTeamCertificateForTeam(workingDir, active)
		}
	}
	if cert == nil {
		if workspace, teamState, _, err := awconfig.LoadWorkspaceAndTeamState(workingDir); err == nil {
			if membership := awconfig.ActiveMembershipFor(workspace, teamState); membership != nil {
				if registryURL == "" && teamState != nil {
					if teamMembership := teamState.Membership(membership.TeamID); teamMembership != nil {
						registryURL = strings.TrimSpace(teamMembership.RegistryURL)
					}
				}
				cert, _ = awconfig.LoadTeamCertificateForTeam(workingDir, membership.TeamID)
			}
		}
	}
	if cert == nil {
		return nil, nil
	}

	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, usageError("current identity has no local signing key")
		}
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	certDID := strings.TrimSpace(cert.MemberDIDKey)
	if certDID == "" {
		return nil, fmt.Errorf("active team certificate is missing member_did_key")
	}
	if certDID != didKey {
		return nil, fmt.Errorf("current signing key did:key %q does not match active team certificate member_did_key %q", didKey, certDID)
	}
	identityScope := awid.NormalizeIdentityScope(firstNonEmpty(cert.IdentityScope, cert.Lifetime))
	if identityScope != awid.IdentityModeGlobal && identityScope != awid.IdentityModeLocal {
		identityScope = awid.IdentityModeLocal
	}
	lifetime := awid.LegacyLifetimeForIdentityScope(identityScope)
	if registryURL == "" {
		if identity, _, err := awconfig.LoadWorktreeIdentityFromDir(workingDir); err == nil && identity != nil {
			registryURL = strings.TrimSpace(identity.RegistryURL)
		}
	}
	resolved := &awconfig.ResolvedIdentity{
		WorkingDir:     strings.TrimSpace(workingDir),
		SigningKeyPath: signingKeyPath,
		DID:            didKey,
		StableID:       strings.TrimSpace(cert.MemberDIDAW),
		Address:        strings.TrimSpace(cert.MemberAddress),
		Custody:        awid.CustodySelf,
		IdentityScope:  identityScope,
		Lifetime:       lifetime,
		RegistryURL:    registryURL,
	}
	if domain, handle, ok := awconfig.CutIdentityAddress(resolved.Address); ok {
		resolved.Domain = domain
		resolved.Handle = handle
	} else if resolved.Address != "" {
		resolved.Handle = resolved.Address
	}
	return resolved, nil
}

func createLocalEncryptionKeyRecord(identity *awconfig.ResolvedIdentity, signingKey ed25519.PrivateKey, previousKeyID string) (*awconfig.EncryptionKeyRecord, *awid.EncryptionKeyAssertion, error) {
	priv, rawPub, err := awid.GenerateX25519Keypair()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	assertion, err := awid.BuildEncryptionKeyAssertion(signingKey, strings.TrimSpace(identity.DID), strings.TrimSpace(identity.StableID), rawPub, previousKeyID, now)
	if err != nil {
		return nil, nil, err
	}
	privateRel := awconfig.WorktreeEncryptionPrivateKeyRelativePath(assertion.EncryptionKeyID)
	privatePath := filepath.Join(identity.WorkingDir, privateRel)
	if err := awid.SaveX25519PrivateKey(privatePath, priv); err != nil {
		return nil, nil, err
	}
	assertionRel := awconfig.WorktreeEncryptionAssertionRelativePath(assertion.EncryptionKeyID)
	assertionPath := filepath.Join(identity.WorkingDir, assertionRel)
	if err := saveEncryptionAssertion(assertionPath, assertion); err != nil {
		return nil, nil, err
	}
	return &awconfig.EncryptionKeyRecord{
		KeyID:          assertion.EncryptionKeyID,
		PublicKey:      assertion.EncryptionPublicKey,
		PrivateKeyPath: privateRel,
		AssertionPath:  assertionRel,
		CreatedAt:      assertion.CreatedAt,
		NotBefore:      assertion.NotBefore,
		ExpiresAt:      assertion.ExpiresAt,
	}, assertion, nil
}

type encryptionRecordKeyMaterial struct {
	KeyID     string
	PublicKey string
}

func validateEncryptionRecordPrivateKey(root string, record *awconfig.EncryptionKeyRecord) (*encryptionRecordKeyMaterial, error) {
	if record == nil {
		return nil, usageError("local E2E encryption key state has no active key; run `aw id encryption-key setup`")
	}
	privatePath := resolveWorktreeRelativePath(root, record.PrivateKeyPath)
	priv, err := awid.LoadX25519PrivateKey(privatePath)
	if err != nil {
		return nil, usageError("local E2E encryption private key is missing or unreadable at %s; restore it from backup before publishing this key, or run `aw id encryption-key rotate` to publish a new key", privatePath)
	}
	rawPub := priv.PublicKey().Bytes()
	keyID, err := awid.ComputeEncryptionKeyID(rawPub)
	if err != nil {
		return nil, err
	}
	publicKey := base64.RawStdEncoding.EncodeToString(rawPub)
	if keyID != strings.TrimSpace(record.KeyID) {
		return nil, usageError("local E2E encryption private key at %s does not match active key %s; restore the matching archived key or rotate", privatePath, strings.TrimSpace(record.KeyID))
	}
	if publicKey != strings.TrimSpace(record.PublicKey) {
		return nil, usageError("local E2E encryption private key at %s does not match active public key metadata; restore the matching archived key or rotate", privatePath)
	}
	return &encryptionRecordKeyMaterial{KeyID: keyID, PublicKey: publicKey}, nil
}

func validateEncryptionRecordAssertion(identity *awconfig.ResolvedIdentity, record *awconfig.EncryptionKeyRecord, assertion *awid.EncryptionKeyAssertion, material *encryptionRecordKeyMaterial) error {
	if identity == nil || record == nil || assertion == nil || material == nil {
		return usageError("local E2E encryption key state is incomplete; restore from backup or run `aw id encryption-key rotate`")
	}
	if err := awid.VerifyEncryptionKeyAssertion(assertion, strings.TrimSpace(identity.DID), strings.TrimSpace(identity.StableID), time.Now().UTC()); err != nil {
		return usageError("local E2E encryption-key assertion is stale or mismatched; restore the matching assertion from backup or run `aw id encryption-key rotate`: %v", err)
	}
	if strings.TrimSpace(assertion.EncryptionKeyID) != strings.TrimSpace(record.KeyID) ||
		strings.TrimSpace(assertion.EncryptionKeyID) != material.KeyID ||
		strings.TrimSpace(assertion.EncryptionPublicKey) != strings.TrimSpace(record.PublicKey) ||
		strings.TrimSpace(assertion.EncryptionPublicKey) != material.PublicKey {
		return usageError("local E2E encryption-key assertion does not match the active private key; restore the matching assertion from backup or run `aw id encryption-key rotate` before publishing")
	}
	return nil
}

func publishIdentityEncryptionKey(ctx context.Context, identity *awconfig.ResolvedIdentity, signingKey ed25519.PrivateKey, assertion *awid.EncryptionKeyAssertion) ([]string, []string, error) {
	published := []string{}
	skipped := []string{}

	if strings.TrimSpace(identity.StableID) != "" {
		registry, err := resolveIdentityRegistryClient(identity)
		if err != nil {
			return nil, nil, err
		}
		registryURL, err := currentIdentityRegistryURL(ctx, identity, registry)
		if err != nil {
			if errors.Is(err, errMissingIdentityRegistryContext) {
				skipped = append(skipped, "awid: global identity is missing registry_url or address domain; cannot safely choose a registry")
			} else {
				return nil, nil, err
			}
		} else if err := registry.PublishEncryptionKey(ctx, registryURL, identity.StableID, assertion); err != nil {
			return nil, nil, fmt.Errorf("publish encryption key to awid: %w", err)
		} else {
			published = append(published, "awid:"+registryURL)
		}
	} else {
		skipped = append(skipped, "awid: local identity has no did:aw")
	}

	if hasWorkspaceBinding(identity.WorkingDir) {
		client, _, err := resolveClientSelectionForDir(identity.WorkingDir)
		if err != nil {
			return nil, nil, err
		}
		if _, err := client.PublishMyEncryptionKey(ctx, assertion); err != nil {
			return nil, nil, fmt.Errorf("publish encryption key to aweb service: %w", err)
		}
		published = append(published, "aweb-service")
	} else {
		skipped = append(skipped, "aweb-service: no workspace binding")
	}

	if len(published) == 0 {
		skipped = append(skipped, "no public discovery target was available; run this again after joining or registering with a service")
	}
	return published, skipped, nil
}

func hasWorkspaceBinding(workingDir string) bool {
	workspace, teamState, _, err := awconfig.LoadWorkspaceAndTeamState(workingDir)
	if err != nil || workspace == nil {
		return false
	}
	return awconfig.ActiveMembershipFor(workspace, teamState) != nil
}

func saveEncryptionAssertion(path string, assertion *awid.EncryptionKeyAssertion) error {
	data, err := json.MarshalIndent(assertion, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return awid.AtomicWriteFile(path, data)
}

func loadEncryptionAssertion(root, relPath string) (*awid.EncryptionKeyAssertion, error) {
	path := resolveWorktreeRelativePath(root, relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read encryption key assertion %s: %w", path, err)
	}
	var assertion awid.EncryptionKeyAssertion
	if err := json.Unmarshal(data, &assertion); err != nil {
		return nil, fmt.Errorf("parse encryption key assertion %s: %w", path, err)
	}
	return &assertion, nil
}

func resolveWorktreeRelativePath(root, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, filepath.FromSlash(path))
}

func encryptionKeyBackupWarning() string {
	return "Back up .aw/encryption-keys with this workspace. Losing archived E2E encryption keys makes old encrypted messages unrecoverable; AC/aweb cannot recover them."
}
