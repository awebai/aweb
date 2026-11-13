package main

import (
	"context"
	"crypto/ed25519"
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

// A registered identity with no address (human-assurance-contract.md
// section 2): a fresh self-custodial key that registers its own did:aw
// mapping at the chosen registry and claims no namespace address, so no
// namespace controller key is needed. It is what a deployment root is before
// a human endorses it. Creation is resumable: the key is kept privately
// before anything is sent, so a run killed at any point is completed by the
// next with the same key, never replaced by a second identity.
//
// A local identity is the same creation registered nowhere: a key-only home
// (a did:key, no did:aw, address, registry or membership) that the
// parent/child exchange and a team admission take as a local agent. A rerun
// on a home holding exactly that identity returns it.

const unaddressedStateFile = "unaddressed-identity-create.json"

// unaddressedCreationState marks a creation in progress and the registry it
// registers at. It holds no key material: the key is the home's signing.key,
// installed before anything is sent.
type unaddressedCreationState struct {
	Version     int    `json:"version"`
	RegistryURL string `json:"registry_url"`
}

// unaddressedCreate is one creation into Root at RegistryURL, or, with no
// Registry, of a local identity.
type unaddressedCreate struct {
	Root        string
	RegistryURL string
	Registry    *awid.RegistryClient
}

func identityExists(format string, args ...any) error {
	return withErrorCode("identity_exists", fmt.Errorf(format, args...))
}

// createUnaddressedIdentity creates, or completes an interrupted creation of,
// the identity in c.Root. A home that holds a complete identity, a key it did
// not create here, a creation for another registry or anything else refuses
// identity_exists before anything is sent.
func createUnaddressedIdentity(ctx context.Context, c unaddressedCreate) (map[string]any, error) {
	statePath := filepath.Join(c.Root, unaddressedStateFile)
	local := c.Registry == nil
	existing := func() map[string]any {
		if didKey, ok := keyOnlyIdentity(c.Root); local && ok {
			return map[string]any{"status": "already_exists", "did_key": didKey, "identity_home": c.Root}
		}
		return nil
	}
	if result := existing(); result != nil {
		return result, nil
	}
	// Checked before the lock is taken as well as under it, so a refused home
	// is left exactly as it was.
	if _, err := unaddressedHomeRefusal(c, statePath); err != nil {
		return nil, err
	}
	lock, err := awconfig.TryLockExclusive(statePath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("identity creation already in progress in %s, or its lock is unavailable: %w", c.Root, err)
	}
	defer lock.Close()
	if result := existing(); result != nil {
		return result, nil
	}
	key, resumed, err := unaddressedKey(c, statePath)
	if err != nil {
		return nil, err
	}
	public := key.Public().(ed25519.PublicKey)
	didKey := awid.ComputeDIDKey(public)
	status := "created"
	if resumed {
		status = "resumed"
	}
	result := map[string]any{"status": status, "did_key": didKey, "identity_home": c.Root}
	identity := &awconfig.WorktreeIdentity{DID: didKey, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal,
		CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if !local {
		stableID := awid.ComputeStableID(public)
		if err := registerUnaddressedIdentity(ctx, c, key, didKey, stableID); err != nil {
			return nil, err
		}
		identity.StableID, identity.IdentityScope = stableID, awid.IdentityModeGlobal
		identity.RegistryURL, identity.RegistryStatus = c.RegistryURL, "registered"
		result["did_aw"], result["registry_url"] = stableID, c.RegistryURL
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(c.Root, "identity.yaml"), identity); err != nil {
		return nil, err
	}
	if err := os.Remove(statePath); err != nil {
		return nil, err
	}
	return result, nil
}

// registerUnaddressedIdentity registers stableID's mapping to didKey at
// c.RegistryURL and confirms it there.
func registerUnaddressedIdentity(ctx context.Context, c unaddressedCreate, key ed25519.PrivateKey, didKey, stableID string) error {
	// An earlier run may already have registered it; the read-back decides.
	_, err := c.Registry.RegisterIdentity(ctx, c.RegistryURL, didKey, stableID, key)
	var registered *awid.AlreadyRegisteredError
	if err != nil && !errors.As(err, &registered) {
		return fmt.Errorf("register %s at %s: %w", stableID, c.RegistryURL, err)
	}
	// The registry's own answer, not the registration's, confirms the mapping:
	// one held for another key completes nothing and leaves the creation
	// resumable.
	resolution, err := c.Registry.ResolveKeyAt(ctx, c.RegistryURL, stableID)
	if err != nil {
		return fmt.Errorf("read back %s at %s: %w", stableID, c.RegistryURL, err)
	}
	if resolution.DIDAW != stableID || resolution.CurrentDIDKey != didKey {
		return fmt.Errorf("%s reads back at %s with key %s, not this identity's", stableID, c.RegistryURL, resolution.CurrentDIDKey)
	}
	return nil
}

// keyOnlyIdentity is the did:key of the complete local identity root holds,
// when root holds exactly that: its identity file, its key and the creation
// lock, and nothing else.
func keyOnlyIdentity(root string) (string, bool) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "identity.yaml", "signing.key", unaddressedStateFile + ".lock":
		default:
			return "", false
		}
	}
	if info, err := os.Lstat(filepath.Join(root, "identity.yaml")); err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(root, "identity.yaml"))
	if err != nil || identity.Custody != awid.CustodySelf || identity.IdentityScope != awid.IdentityModeLocal ||
		identity.StableID != "" || identity.Address != "" || identity.RegistryURL != "" {
		return "", false
	}
	key, err := awid.LoadSigningKey(filepath.Join(root, "signing.key"))
	if err != nil || awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != identity.DID {
		return "", false
	}
	return identity.DID, true
}

// unaddressedHomeRefusal refuses a home that holds an identity, anything this
// creation did not write, or a creation for another registry. It reports
// whether the home holds an interrupted creation to resume.
func unaddressedHomeRefusal(c unaddressedCreate, statePath string) (bool, error) {
	if _, err := os.Lstat(filepath.Join(c.Root, "identity.yaml")); err == nil {
		return false, identityExists("%s already holds an identity; it is used as it is", c.Root)
	}
	raw, err := os.ReadFile(statePath)
	resumed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	// The home holds nothing this creation did not write: its lock, and once
	// marked, its state and key.
	owned := map[string]bool{unaddressedStateFile + ".lock": true}
	if resumed {
		owned[unaddressedStateFile], owned["signing.key"] = true, true
	}
	entries, err := os.ReadDir(c.Root)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !owned[entry.Name()] {
			return false, identityExists("%s holds %s, which this creation did not write; an identity is created only in its own home", c.Root, entry.Name())
		}
	}
	if !resumed {
		return false, nil
	}
	var state unaddressedCreationState
	if json.Unmarshal(raw, &state) != nil || state.Version != 1 {
		return false, errors.New("the interrupted identity creation's state is not valid; keep the home for inspection")
	}
	if state.RegistryURL != c.RegistryURL {
		return false, identityExists("%s holds a creation for registry %s, not %s", c.Root, state.RegistryURL, c.RegistryURL)
	}
	return true, nil
}

// unaddressedKey is the key of the creation in c.Root. A fresh creation is
// marked first and its key installed next; an interrupted one resumes with
// its installed key, or, killed before the key was installed (when nothing
// can have been registered), installs a fresh one. It reports whether the
// creation was resumed.
func unaddressedKey(c unaddressedCreate, statePath string) (ed25519.PrivateKey, bool, error) {
	resumed, err := unaddressedHomeRefusal(c, statePath)
	if err != nil {
		return nil, false, err
	}
	if !resumed {
		data, err := json.Marshal(unaddressedCreationState{Version: 1, RegistryURL: c.RegistryURL})
		if err != nil {
			return nil, false, err
		}
		if err := awid.AtomicWriteFile(statePath, data); err != nil {
			return nil, false, err
		}
	}
	keyPath := filepath.Join(c.Root, "signing.key")
	key, err := awid.LoadSigningKey(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		_, key, err = awid.GenerateKeypair()
		if err != nil {
			return nil, false, err
		}
		return key, resumed, awid.SaveSigningKeyExclusive(keyPath, key)
	}
	return key, resumed, err
}

var idCreateNoAddress, idCreateLocal bool

// identityParentFlags name an address, a hosted organization or an issuing
// parent, none of which an addressless creation takes.
var identityParentFlags = []string{"name", "domain", "org", "owner-identity-home", "team-id", "inbound-mode", "human-parent", "root-parent", "skip-dns-verify"}

func refuseCreateFlags(cmd *cobra.Command, mode, what string, flags []string) error {
	for _, flag := range flags {
		if cmd.Flags().Changed(flag) {
			return usageError("%s creates %s; --%s does not apply", mode, what, flag)
		}
	}
	return nil
}

// unaddressedFlagsRefusal refuses a --no-address creation without an explicit
// identity home and registry, or combined with any flag that names an
// address, a hosted organization or an issuing parent.
func unaddressedFlagsRefusal(cmd *cobra.Command, explicitHome bool) error {
	if err := refuseCreateFlags(cmd, "--no-address", "an identity with no address, organization or parent", identityParentFlags); err != nil {
		return err
	}
	if registry, _ := cmd.Flags().GetString("registry"); strings.TrimSpace(registry) == "" {
		return usageError("--no-address requires --registry: the registry origin its did:aw is registered at")
	}
	if !explicitHome {
		return usageError("--no-address requires an explicit --identity-home for the new identity")
	}
	return nil
}

// localFlagsRefusal refuses a --local creation without an explicit identity
// home, or combined with a registry or any flag that names an address, a
// hosted organization or an issuing parent.
func localFlagsRefusal(cmd *cobra.Command, explicitHome bool) error {
	flags := append([]string{"registry", "no-address"}, identityParentFlags...)
	if err := refuseCreateFlags(cmd, "--local", "a key-only identity registered nowhere, with no address, organization or parent", flags); err != nil {
		return err
	}
	if !explicitHome {
		return usageError("--local requires an explicit --identity-home for the new identity")
	}
	return nil
}

// runUnaddressedIdentityCreate runs a --no-address creation, or a --local one
// when local.
func runUnaddressedIdentityCreate(cmd *cobra.Command, local bool) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	refusal := unaddressedFlagsRefusal
	if local {
		refusal = localFlagsRefusal
	}
	if err := refusal(cmd, home.Source == awconfig.IdentityHomeFlag); err != nil {
		return err
	}
	create := unaddressedCreate{Root: home.Root}
	if !local {
		create.RegistryURL, err = awid.CanonicalServerOrigin(strings.TrimSpace(idCreateRegistryURL))
		if err != nil {
			return usageError("--registry: %v", err)
		}
		create.Registry, err = newConfiguredRegistryClient(nil)
		if err != nil {
			return err
		}
		// The operator names this registry explicitly, as a protected profile pins it.
		if err := create.Registry.TrustRegistryOrigin(create.RegistryURL); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(home.Root, 0o700); err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	result, err := createUnaddressedIdentity(ctx, create)
	if err != nil {
		return err
	}
	printOutput(result, func(any) string {
		if local {
			return fmt.Sprintf("Local identity %s with key %s, registered nowhere, in %s\n", result["status"], result["did_key"], home.Root)
		}
		return fmt.Sprintf("Identity %s %s with key %s at %s, with no address, in %s\n", result["did_aw"], result["status"], result["did_key"], create.RegistryURL, home.Root)
	})
	return nil
}
