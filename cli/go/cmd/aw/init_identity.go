package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type initIdentityMaterial struct {
	Existing       bool
	Persistent     bool
	PublicKey      ed25519.PublicKey
	SigningKey     ed25519.PrivateKey
	DID            string
	StableID       string
	Handle         string
	Address        string
	IdentityPath   string
	SigningKeyPath string
	RegistryURL    string
	CreatedAt      string
}

func detectExistingPersistentIdentityHandle(workingDir string) (string, bool, error) {
	identity, err := loadExistingPersistentInitIdentity(workingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return identity.Handle, true, nil
}

func prepareInitIdentityMaterial(opts initOptions, lifetime string) (*initIdentityMaterial, error) {
	if strings.TrimSpace(lifetime) == awid.LifetimePersistent {
		existing, err := loadExistingPersistentInitIdentity(opts.WorkingDir)
		if err == nil {
			return existing, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		return createNewPersistentInitIdentity(opts.WorkingDir, strings.TrimSpace(opts.IdentityName))
	}

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	return &initIdentityMaterial{
		PublicKey:      pub,
		SigningKey:     priv,
		DID:            awid.ComputeDIDKey(pub),
		SigningKeyPath: awconfig.WorktreeSigningKeyPath(opts.WorkingDir),
	}, nil
}

func createNewPersistentInitIdentity(workingDir, handle string) (*initIdentityMaterial, error) {
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return &initIdentityMaterial{
		Existing:       false,
		Persistent:     true,
		PublicKey:      pub,
		SigningKey:     priv,
		DID:            awid.ComputeDIDKey(pub),
		StableID:       awid.ComputeStableID(pub),
		Handle:         strings.TrimSpace(handle),
		IdentityPath:   filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()),
		SigningKeyPath: awconfig.WorktreeSigningKeyPath(workingDir),
		CreatedAt:      now,
	}, nil
}

func loadExistingPersistentInitIdentity(workingDir string) (*initIdentityMaterial, error) {
	identity, identityPath, err := awconfig.LoadWorktreeIdentityFromDir(workingDir)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(identity.Custody) != awid.CustodySelf {
		return nil, fmt.Errorf("existing %s must be self-custodial", identityPath)
	}
	if strings.TrimSpace(identity.Lifetime) != awid.LifetimePersistent {
		return nil, fmt.Errorf("existing %s must describe a persistent identity", identityPath)
	}
	address := strings.TrimSpace(identity.Address)
	if address == "" {
		return nil, fmt.Errorf("existing %s is missing address", identityPath)
	}
	handle := handleFromAddress(address)
	if handle == "" {
		return nil, fmt.Errorf("existing %s has invalid address %q", identityPath, address)
	}

	root := awconfig.WorktreeRootFromIdentityPath(identityPath)
	signingKeyPath := awconfig.WorktreeSigningKeyPath(root)
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load worktree signing key: %w", err)
	}
	pub := signingKey.Public().(ed25519.PublicKey)
	did := awid.ComputeDIDKey(pub)
	if strings.TrimSpace(identity.DID) != did {
		return nil, fmt.Errorf("%s did %q does not match %s", identityPath, identity.DID, did)
	}
	stableID := awid.ComputeStableID(pub)
	if strings.TrimSpace(identity.StableID) != stableID {
		return nil, fmt.Errorf("%s stable_id %q does not match %s", identityPath, identity.StableID, stableID)
	}

	return &initIdentityMaterial{
		Existing:       true,
		Persistent:     true,
		PublicKey:      pub,
		SigningKey:     signingKey,
		DID:            did,
		StableID:       stableID,
		Handle:         handle,
		Address:        address,
		IdentityPath:   identityPath,
		SigningKeyPath: signingKeyPath,
		RegistryURL:    strings.TrimSpace(identity.RegistryURL),
		CreatedAt:      strings.TrimSpace(identity.CreatedAt),
	}, nil
}

func persistentIdentityHandleForBootstrap(opts initOptions) (string, error) {
	handle := strings.TrimSpace(opts.IdentityName)
	existingHandle, exists, err := detectExistingPersistentIdentityHandle(opts.WorkingDir)
	if err != nil {
		return "", err
	}
	if !exists {
		return handle, nil
	}
	if handle != "" && handle != existingHandle {
		return "", usageError("--name %q does not match existing .aw/identity.yaml name %q", handle, existingHandle)
	}
	return existingHandle, nil
}

func validatePersistentBootstrapResponse(identity *initIdentityMaterial, resp *awid.BootstrapIdentityResponse) error {
	if identity == nil || resp == nil {
		return fmt.Errorf("missing persistent identity response state")
	}
	if strings.TrimSpace(resp.DID) != identity.DID {
		return fmt.Errorf("bootstrap returned did %q, expected %q", resp.DID, identity.DID)
	}
	if strings.TrimSpace(resp.StableID) != identity.StableID {
		return fmt.Errorf("bootstrap returned stable_id %q, expected %q", resp.StableID, identity.StableID)
	}
	if handle := strings.TrimSpace(resp.IdentityHandle()); handle != identity.Handle {
		return fmt.Errorf("bootstrap returned handle %q, expected %q", handle, identity.Handle)
	}
	if identity.Existing && strings.TrimSpace(identity.Address) != "" && strings.TrimSpace(resp.Address) != strings.TrimSpace(identity.Address) {
		return fmt.Errorf("bootstrap returned address %q, expected %q", resp.Address, identity.Address)
	}
	return nil
}

func syncPersistentIdentityRegistry(
	ctx context.Context,
	opts initOptions,
	resp *awid.BootstrapIdentityResponse,
	identity *initIdentityMaterial,
	attachURL string,
) (string, string, error) {
	fallbackURL := strings.TrimSpace(opts.BaseURL)
	if fallbackURL == "" {
		fallbackURL = strings.TrimSpace(attachURL)
	}
	registry, err := newConfiguredRegistryClient(nil, fallbackURL)
	if err != nil {
		return "", "pending", err
	}

	registryURL := strings.TrimSpace(identity.RegistryURL)
	if registryURL == "" {
		domain := persistentRegistryDomain(resp, identity)
		if domain == "" {
			registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
		} else {
			registryURL, err = registry.DiscoverRegistry(ctx, domain)
			if err != nil {
				return "", "pending", fmt.Errorf("could not discover identity registry: %w", err)
			}
		}
	}

	handle := identity.Handle
	if handle == "" {
		handle = handleFromAddress(resp.Address)
	}
	if identity.Existing {
		_, err = registry.UpdateDIDServer(ctx, registryURL, identity.StableID, attachURL, identity.SigningKey)
		if code, ok := registryStatusCode(err); ok && code == http.StatusNotFound {
			err = awid.RegisterSelfCustodialDID(
				ctx,
				registryURL,
				attachURL,
				strings.TrimSpace(resp.Address),
				handle,
				identity.DID,
				identity.StableID,
				identity.SigningKey,
			)
		}
	} else {
		err = awid.RegisterSelfCustodialDID(
			ctx,
			registryURL,
			attachURL,
			strings.TrimSpace(resp.Address),
			handle,
			identity.DID,
			identity.StableID,
			identity.SigningKey,
		)
	}
	if err != nil {
		return registryURL, "pending", err
	}
	return registryURL, "registered", nil
}

func persistentRegistryDomain(resp *awid.BootstrapIdentityResponse, identity *initIdentityMaterial) string {
	if resp != nil {
		if domain, _, ok := cutIdentityAddress(strings.TrimSpace(resp.Address)); ok && strings.Contains(domain, ".") {
			return domain
		}
		if ns := strings.TrimSpace(resp.Namespace); strings.Contains(ns, ".") {
			return ns
		}
	}
	if identity != nil {
		if domain, _, ok := cutIdentityAddress(strings.TrimSpace(identity.Address)); ok && strings.Contains(domain, ".") {
			return domain
		}
	}
	return ""
}

func persistPermanentInitIdentity(identity *initIdentityMaterial, resp *awid.BootstrapIdentityResponse, registryURL, registryStatus string) error {
	if identity == nil || resp == nil {
		return fmt.Errorf("missing persistent identity state")
	}
	if identity.IdentityPath == "" || identity.SigningKeyPath == "" {
		return fmt.Errorf("missing persistent identity paths")
	}
	if !identity.Existing {
		if err := awid.SaveSigningKey(identity.SigningKeyPath, identity.SigningKey); err != nil {
			return err
		}
	}
	createdAt := strings.TrimSpace(identity.CreatedAt)
	if createdAt == "" {
		createdAt = time.Now().UTC().Format(time.RFC3339)
	}
	return awconfig.SaveWorktreeIdentityTo(identity.IdentityPath, &awconfig.WorktreeIdentity{
		DID:            identity.DID,
		StableID:       identity.StableID,
		Address:        strings.TrimSpace(resp.Address),
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    strings.TrimSpace(registryURL),
		RegistryStatus: strings.TrimSpace(registryStatus),
		CreatedAt:      createdAt,
	})
}
