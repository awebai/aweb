package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	SkipDNSVerify       bool                      `json:",omitempty"`
	DefaultTarget       bool                      `json:",omitempty"`
	Progress            *standaloneCreateProgress `json:",omitempty"`
}

type standaloneCreateProgress struct {
	Started          bool
	NamespaceCreated bool
	AddressClaimed   bool
	Refused          bool
}

const standaloneCreateRecoveryFile = "id-create.json"

func standaloneCreateRecoveryPath(identityPath string) string {
	return filepath.Join(filepath.Dir(identityPath), standaloneCreateRecoveryFile)
}

func standaloneCreateRecord(identityPath string) awconfig.RecoveryFile {
	return awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(identityPath)}, Name: standaloneCreateRecoveryFile}
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
	FinishRefusal  bool
}

// loadStandaloneCreateRecovery distinguishes absent state from an unreadable
// retained operation. Only the saved exact selection permits key reuse; read
// failures keep its home for reconciliation (docs/identity.md §Key material and local files).
func loadStandaloneCreateRecovery(input standaloneCreateResume) (result *preparedIDCreate, resultErr error) {
	identityPath, keyPath, workspacePath := input.IdentityPath, input.SigningKeyPath, input.WorkspacePath
	path := standaloneCreateRecoveryPath(identityPath)
	raw, err := standaloneCreateRecord(identityPath).ReadBounded(maxResponseBytes)
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
	if saved.Version != 1 || p == nil || p.Address != p.Domain+"/"+p.Name {
		return nil, usageError("invalid retained ID creation plan at %s; keep the record and its signing key for reconciliation", path)
	}
	if progress := saved.Progress; progress != nil && !progress.Started && (progress.NamespaceCreated || progress.AddressClaimed || progress.Refused) {
		return nil, usageError("invalid retained ID creation progress at %s; keep the record and its signing key for reconciliation", path)
	}
	changed := saved.changedFields(input)
	pathsMatch := p.IdentityPath == identityPath && p.SigningKeyPath == keyPath
	if saved.Progress != nil && saved.Progress.Refused {
		if !input.FinishRefusal || !pathsMatch {
			return nil, usageError("definitively refused ID creation is awaiting local cleanup. %s", saved.retryAdvice())
		}
		if err := saved.clearRefused(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if len(changed) != 0 {
		return nil, usageError("ID creation retry changed %s. %s", strings.Join(changed, ", "), saved.retryAdvice())
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
	controller, err := awconfig.LoadControllerKey(p.Domain)
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
	return &preparedIDCreate{Plan: p, IdentityKey: key, ControllerKey: controller, Recovery: &saved}, nil
}

func (saved *standaloneCreateRecovery) changedFields(input standaloneCreateResume) []string {
	p, opts := saved.Plan, input.Options
	var fields []string
	for _, field := range []struct {
		name    string
		changed bool
	}{
		{"--name", p.Name != input.Name},
		{"--domain", p.Domain != input.Domain},
		{"--identity-home", p.IdentityPath != input.IdentityPath || p.SigningKeyPath != input.SigningKeyPath},
		{"--human-parent", saved.HumanParent != strings.TrimSpace(opts.HumanParent)},
		{"--root-parent", saved.RootParent != opts.RootParent},
		{"--registry", saved.RegistryChoice != strings.TrimSpace(opts.RegistryURL)},
		{"AWID_REGISTRY_URL", saved.RegistryEnvironment != standaloneRegistryEnvironment(opts)},
	} {
		if field.changed {
			fields = append(fields, field.name)
		}
	}
	return fields
}

func (saved *standaloneCreateRecovery) retryAdvice() string {
	p := saved.Plan
	var accepted []string
	if saved.Progress != nil {
		if saved.Progress.NamespaceCreated {
			accepted = append(accepted, "namespace registration for "+p.Domain)
		}
		if saved.Progress.AddressClaimed {
			accepted = append(accepted, "identity and address claim for "+p.Address)
		}
	}
	args := []string{"aw"}
	location := ""
	if saved.DefaultTarget {
		location = fmt.Sprintf(" from %s", filepath.Dir(filepath.Dir(p.IdentityPath)))
	} else {
		args = append(args, "--identity-home", filepath.Dir(p.IdentityPath))
	}
	args = append(args, "id", "create", "--domain", p.Domain, "--name", p.Name)
	if saved.RegistryChoice != "" {
		args = append(args, "--registry", saved.RegistryChoice)
	}
	if saved.HumanParent != "" {
		args = append(args, "--human-parent", saved.HumanParent)
	}
	if saved.RootParent {
		args = append(args, "--root-parent")
	}
	if saved.SkipDNSVerify {
		args = append(args, "--skip-dns-verify")
	}
	command := formatShellCommand(args)
	if saved.RegistryChoice == "" && strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")) != saved.RegistryEnvironment {
		command = "env " + formatShellCommand(append([]string{"AWID_REGISTRY_URL=" + saved.RegistryEnvironment}, args...))
	}
	outcome := "The previous registry outcome may be unknown."
	if saved.Progress != nil && saved.Progress.Refused {
		outcome = "AWID definitively refused the first write."
	} else if len(accepted) != 0 {
		outcome = "AWID accepted " + strings.Join(accepted, " and ") + "."
	}
	return fmt.Sprintf("%s The original key and creation plan are retained in %s. Retry%s with `%s`.", outcome, standaloneCreateRecoveryPath(p.IdentityPath), location, command)
}

func (saved *standaloneCreateRecovery) write() error {
	raw, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	return standaloneCreateRecord(saved.Plan.IdentityPath).Write(raw)
}

func persistStandaloneCreate(prepared *preparedIDCreate, opts idCreateOptions) error {
	if prepared.Recovery != nil {
		return nil
	}
	p := prepared.Plan
	if err := awid.SaveSigningKeyExclusive(p.SigningKeyPath, prepared.IdentityKey); err != nil {
		return err
	}
	saved := &standaloneCreateRecovery{
		Version: 1, Plan: p, HumanParent: strings.TrimSpace(opts.HumanParent), RootParent: opts.RootParent,
		RegistryChoice: strings.TrimSpace(opts.RegistryURL), RegistryEnvironment: standaloneRegistryEnvironment(opts),
		SkipDNSVerify: opts.SkipDNSVerify, DefaultTarget: opts.IdentityHome == nil || !opts.IdentityHome.External(),
		Progress: &standaloneCreateProgress{},
	}
	if err := saved.write(); err != nil {
		return fmt.Errorf("private key retained at %s; no registry write attempted; save creation recovery: %w", p.SigningKeyPath, err)
	}
	prepared.Recovery = saved
	return nil
}

// The record stays until its owned key has been removed. A crash between
// those removals can finish the cleanup before checking the next selection.
func (saved *standaloneCreateRecovery) clearRefused() error {
	p := saved.Plan
	if saved.Progress == nil || !saved.Progress.Refused || saved.Progress.NamespaceCreated || saved.Progress.AddressClaimed {
		return errors.New("cannot clear a creation plan with possible accepted registry effects")
	}
	for _, path := range []string{p.IdentityPath, filepath.Join(filepath.Dir(p.IdentityPath), "workspace.yaml")} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refused creation home now contains %s; retain it for reconciliation", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	key, err := awid.LoadSigningKey(p.SigningKeyPath)
	if err == nil {
		if awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != p.DIDKey {
			return fmt.Errorf("refused creation key at %s changed; retain it for reconciliation", p.SigningKeyPath)
		}
		if err := os.Remove(p.SigningKeyPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return standaloneCreateRecord(p.IdentityPath).Remove()
}

func definitiveStandaloneCreateRefusal(err error) bool {
	code, ok := awid.HTTPStatusCode(err)
	if !ok {
		var conflict *awid.AtomicAddressClaimConflictError
		if errors.As(err, &conflict) {
			code = conflict.StatusCode
		}
	}
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func (p *preparedIDCreate) registerStandaloneCreate(ctx context.Context, registry *awid.RegistryClient) error {
	saved := p.Recovery
	// Old records predate durable write progress. Their outcome must be
	// reconciled with the same selection even if a later request is refused.
	firstAttempt := saved.Progress != nil && !saved.Progress.Started
	if saved.Progress == nil {
		saved.Progress = &standaloneCreateProgress{Started: true}
	}
	progress := saved.Progress
	if progress.AddressClaimed {
		return nil
	}
	beforeWrite := func() error {
		if progress.Started {
			return nil
		}
		progress.Started = true
		if err := saved.write(); err != nil {
			return fmt.Errorf("record start of ID creation: %w", err)
		}
		return nil
	}

	namespace, err := ensureStandaloneNamespaceWithOutcome(ctx, registry, p.Plan, p.ControllerKey, beforeWrite)
	if namespace == standaloneNamespaceCreated {
		progress.NamespaceCreated = true
		if writeErr := saved.write(); writeErr != nil {
			return fmt.Errorf("record accepted namespace registration: %w. %s", errors.Join(err, writeErr), saved.retryAdvice())
		}
	}
	if err != nil {
		return p.finishStandaloneCreateFailure(idCreateAtomicClaimError(p.Plan, err), firstAttempt && namespace == standaloneNamespaceRefused)
	}
	if err := beforeWrite(); err != nil {
		return err
	}
	err = claimStandaloneCreateAddress(ctx, registry, p.Plan, p.ControllerKey, p.IdentityKey)
	if err != nil {
		clear := firstAttempt && !progress.NamespaceCreated && definitiveStandaloneCreateRefusal(err)
		return p.finishStandaloneCreateFailure(idCreateAtomicClaimRecoveryError(p.Plan, err, !clear), clear)
	}
	progress.AddressClaimed = true
	if err := saved.write(); err != nil {
		return fmt.Errorf("record accepted identity and address claim: %w. %s", err, saved.retryAdvice())
	}
	return nil
}

func (p *preparedIDCreate) finishStandaloneCreateFailure(err error, definitiveFirstRefusal bool) error {
	saved := p.Recovery
	if !definitiveFirstRefusal || saved.Progress.NamespaceCreated || saved.Progress.AddressClaimed {
		return fmt.Errorf("%w. %s", err, saved.retryAdvice())
	}
	saved.Progress.Refused = true
	if writeErr := saved.write(); writeErr != nil {
		return errors.Join(err, fmt.Errorf("record definitive ID creation refusal: %w", writeErr))
	}
	if clearErr := saved.clearRefused(); clearErr != nil {
		return errors.Join(err, fmt.Errorf("clear definitively refused ID creation: %w. %s", clearErr, saved.retryAdvice()))
	}
	p.Recovery = nil
	return err
}
