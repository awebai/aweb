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

const unaddressedStateFile = "unaddressed-identity-create.json"

// unaddressedCreationState marks a creation in progress and the registry it
// registers at. It holds no key material: the key is the home's signing.key,
// installed before anything is sent.
type unaddressedCreationState struct {
	Version     int    `json:"version"`
	RegistryURL string `json:"registry_url"`
}

// unaddressedCreate is one creation into Root at RegistryURL.
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
	lock, err := awconfig.TryLockExclusive(statePath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("identity creation already in progress in %s, or its lock is unavailable: %w", c.Root, err)
	}
	defer lock.Close()
	key, resumed, err := unaddressedKey(c, statePath)
	if err != nil {
		return nil, err
	}
	public := key.Public().(ed25519.PublicKey)
	didKey, stableID := awid.ComputeDIDKey(public), awid.ComputeStableID(public)
	// An earlier run may already have registered it; the read-back decides.
	_, err = c.Registry.RegisterIdentity(ctx, c.RegistryURL, didKey, stableID, key)
	var registered *awid.AlreadyRegisteredError
	if err != nil && !errors.As(err, &registered) {
		return nil, fmt.Errorf("register %s at %s: %w", stableID, c.RegistryURL, err)
	}
	// The registry's own answer, not the registration's, confirms the mapping:
	// one held for another key completes nothing and leaves the creation
	// resumable.
	resolution, err := c.Registry.ResolveKeyAt(ctx, c.RegistryURL, stableID)
	if err != nil {
		return nil, fmt.Errorf("read back %s at %s: %w", stableID, c.RegistryURL, err)
	}
	if resolution.DIDAW != stableID || resolution.CurrentDIDKey != didKey {
		return nil, fmt.Errorf("%s reads back at %s with key %s, not this identity's", stableID, c.RegistryURL, resolution.CurrentDIDKey)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(c.Root, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID: didKey, StableID: stableID, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal,
		RegistryURL: c.RegistryURL, RegistryStatus: "registered", CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return nil, err
	}
	if err := os.Remove(statePath); err != nil {
		return nil, err
	}
	status := "created"
	if resumed {
		status = "resumed"
	}
	return map[string]any{"status": status, "did_aw": stableID, "did_key": didKey, "registry_url": c.RegistryURL, "identity_home": c.Root}, nil
}

// unaddressedKey is the key of the creation in c.Root. A fresh creation is
// marked first and its key installed next; an interrupted one resumes with
// its installed key, or, killed before the key was installed (when nothing
// can have been registered), installs a fresh one. It reports whether the
// creation was resumed.
func unaddressedKey(c unaddressedCreate, statePath string) (ed25519.PrivateKey, bool, error) {
	keyPath := filepath.Join(c.Root, "signing.key")
	if _, err := os.Stat(filepath.Join(c.Root, "identity.yaml")); err == nil {
		return nil, false, identityExists("%s already holds an identity; it is used as it is", c.Root)
	}
	raw, err := os.ReadFile(statePath)
	resumed := err == nil
	// The home holds nothing this creation did not write: its lock, and once
	// marked, its state and key. Checked before any key or registry use.
	owned := map[string]bool{unaddressedStateFile + ".lock": true}
	if resumed {
		owned[unaddressedStateFile], owned["signing.key"] = true, true
	}
	entries, dirErr := os.ReadDir(c.Root)
	if dirErr != nil {
		return nil, false, dirErr
	}
	for _, entry := range entries {
		if !owned[entry.Name()] {
			return nil, false, identityExists("%s holds %s, which this creation did not write; an identity is created only in its own home", c.Root, entry.Name())
		}
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		data, err := json.Marshal(unaddressedCreationState{Version: 1, RegistryURL: c.RegistryURL})
		if err != nil {
			return nil, false, err
		}
		if err := awid.AtomicWriteFile(statePath, data); err != nil {
			return nil, false, err
		}
	case err != nil:
		return nil, false, err
	default:
		var state unaddressedCreationState
		if json.Unmarshal(raw, &state) != nil || state.Version != 1 {
			return nil, false, errors.New("the interrupted identity creation's state is not valid; keep the home for inspection")
		}
		if state.RegistryURL != c.RegistryURL {
			return nil, false, identityExists("%s holds a creation for registry %s, not %s", c.Root, state.RegistryURL, c.RegistryURL)
		}
	}
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

var idCreateNoAddress bool

// unaddressedFlagsRefusal refuses a --no-address creation without an explicit
// identity home and registry, or combined with any flag that names an
// address, a hosted organization or an issuing parent.
func unaddressedFlagsRefusal(cmd *cobra.Command, explicitHome bool) error {
	for _, flag := range []string{"name", "domain", "org", "owner-identity-home", "team-id", "inbound-mode", "human-parent", "root-parent", "skip-dns-verify"} {
		if cmd.Flags().Changed(flag) {
			return usageError("--no-address creates an identity with no address, organization or parent; --%s does not apply", flag)
		}
	}
	if registry, _ := cmd.Flags().GetString("registry"); strings.TrimSpace(registry) == "" {
		return usageError("--no-address requires --registry: the registry origin its did:aw is registered at")
	}
	if !explicitHome {
		return usageError("--no-address requires an explicit --identity-home for the new identity")
	}
	return nil
}

func runUnaddressedIdentityCreate(cmd *cobra.Command) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if err := unaddressedFlagsRefusal(cmd, home.Source == awconfig.IdentityHomeFlag); err != nil {
		return err
	}
	registryURL, err := awid.CanonicalServerOrigin(strings.TrimSpace(idCreateRegistryURL))
	if err != nil {
		return usageError("--registry: %v", err)
	}
	if err := os.MkdirAll(home.Root, 0o700); err != nil {
		return err
	}
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	// The operator names this registry explicitly, as a protected profile pins it.
	if err := registry.TrustRegistryOrigin(registryURL); err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	result, err := createUnaddressedIdentity(ctx, unaddressedCreate{Root: home.Root, RegistryURL: registryURL, Registry: registry})
	if err != nil {
		return err
	}
	printOutput(result, func(any) string {
		return fmt.Sprintf("Identity %s %s with key %s at %s, with no address, in %s\n", result["did_aw"], result["status"], result["did_key"], registryURL, home.Root)
	})
	return nil
}
