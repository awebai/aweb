package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// The public plan is saved beside the private key before any registry write.
// Only this constructor's retained plan permits reuse of an existing key.
type standaloneCreateRecovery struct {
	Version             int
	Plan                *idCreatePlan
	HumanParent         string
	RootParent          bool
	RegistryChoice      string
	RegistryEnvironment string
}

func standaloneCreateRecoveryPath(identityPath string) string {
	return filepath.Join(filepath.Dir(identityPath), "id-create.json")
}

func standaloneRegistryEnvironment(opts idCreateOptions) string {
	if strings.TrimSpace(opts.RegistryURL) != "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL"))
}

type standaloneCreateResume struct {
	IdentityPath   string
	SigningKeyPath string
	WorkspacePath  string
	Name           string
	Domain         string
	Options        idCreateOptions
}

// loadStandaloneCreateRecovery distinguishes absent state from an unreadable
// retained operation. Only the saved exact selection permits key reuse; read
// failures keep its home for reconciliation (docs/identity.md §Key material and local files).
func loadStandaloneCreateRecovery(input standaloneCreateResume) (result *preparedIDCreate, resultErr error) {
	identityPath, keyPath, workspacePath := input.IdentityPath, input.SigningKeyPath, input.WorkspacePath
	name, domain, opts := input.Name, input.Domain, input.Options
	path := standaloneCreateRecoveryPath(identityPath)
	raw, err := (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(path)}, Name: filepath.Base(path)}).ReadBounded(maxResponseBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	defer func() {
		if resultErr != nil {
			resultErr = retainIdentityForRecovery(resultErr)
		}
	}()
	if err != nil {
		return nil, err
	}
	var saved standaloneCreateRecovery
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, fmt.Errorf("read retained ID creation: %w", err)
	}
	p := saved.Plan
	if saved.Version != 1 || p == nil || p.IdentityPath != identityPath || p.SigningKeyPath != keyPath || p.Name != name || p.Domain != domain || p.Address != domain+"/"+name || saved.HumanParent != strings.TrimSpace(opts.HumanParent) || saved.RootParent != opts.RootParent || saved.RegistryChoice != strings.TrimSpace(opts.RegistryURL) || saved.RegistryEnvironment != standaloneRegistryEnvironment(opts) {
		return nil, usageError("ID creation retry changed its original address, registry, parent or target; retain %s and retry the original selection", path)
	}
	if _, err := os.Stat(workspacePath); err == nil {
		return nil, usageError("ID creation recovery target already has a workspace at %s", workspacePath)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := awid.LoadSigningKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("restore the original ID creation signing key at %s: %w", keyPath, err)
	}
	pub := key.Public().(ed25519.PublicKey)
	if p.DIDKey != awid.ComputeDIDKey(pub) || p.DIDAW != awid.ComputeStableID(pub) {
		return nil, usageError("retained ID creation key does not match %s", path)
	}
	controller, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return nil, err
	}
	if p.ControllerDID != awid.ComputeDIDKey(controller.Public().(ed25519.PublicKey)) {
		return nil, usageError("retained ID creation namespace controller changed")
	}
	if existing, err := awconfig.LoadWorktreeIdentityFrom(identityPath); err == nil {
		if existing.DID != p.DIDKey || existing.StableID != p.DIDAW || existing.Address != p.Address {
			return nil, usageError("retained ID creation identity changed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &preparedIDCreate{Plan: p, IdentityKey: key, ControllerKey: controller, Retained: true}, nil
}

func persistStandaloneCreate(prepared *preparedIDCreate, opts idCreateOptions) error {
	if prepared.Retained {
		return nil
	}
	p := prepared.Plan
	if err := awid.SaveSigningKeyExclusive(p.SigningKeyPath, prepared.IdentityKey); err != nil {
		return err
	}
	saved := standaloneCreateRecovery{Version: 1, Plan: p, HumanParent: strings.TrimSpace(opts.HumanParent), RootParent: opts.RootParent, RegistryChoice: strings.TrimSpace(opts.RegistryURL), RegistryEnvironment: standaloneRegistryEnvironment(opts)}
	raw, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	record := awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(p.IdentityPath)}, Name: "id-create.json"}
	if err := record.Write(raw); err != nil {
		return fmt.Errorf("private key retained at %s; no registry write attempted; save creation recovery: %w", p.SigningKeyPath, err)
	}
	prepared.Retained = true
	return nil
}
