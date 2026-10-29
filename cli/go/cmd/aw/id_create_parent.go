package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// An agent created with --parent-human carries a chain from creation
// (docs/id-certificates.md §6, "Immediate init/spawn signs directly"): the
// named human signs the agent's certificate, records it in its own issuance
// log before releasing it, and the agent registers it with its own key
// proof. The human is named explicitly; a human record found on disk is
// never attached on its own.

// humanParent is a registered human on this machine that may issue: its
// record and its installed chain.
type humanParent struct {
	record *awconfig.HumanRecord
	dir    string
	chain  *awconfig.InstalledIDChain
}

// loadHumanParent loads the human named id in domain. Only a human whose
// registration completed, with its chain installed, can issue children.
func loadHumanParent(domain, id string) (*humanParent, error) {
	rec, err := awconfig.LoadHumanRecord(domain, id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, usageError("no human %s in %s on this machine (create it with `aw id human init`)", id, domain)
	}
	if rec.State != awconfig.HumanRegistered {
		return nil, usageError("human %s is not registered yet (%s); finish `aw id human init --domain %s` first", id, rec.State, domain)
	}
	dir, err := awconfig.HumanRecordDir(domain, id)
	if err != nil {
		return nil, err
	}
	chain, err := awconfig.LoadInstalledIDChain(dir)
	if err != nil {
		return nil, err
	}
	if chain == nil {
		return nil, fmt.Errorf("human %s has no installed chain in %s", id, dir)
	}
	return &humanParent{record: rec, dir: dir, chain: chain}, nil
}

// humanParentEvidence verifies the human's current chain and key against
// fresh status from registryURL before anything is signed for a child.
func (p *humanParent) evidence(ctx context.Context, registry *awid.RegistryClient, resolver awid.TXTResolver, registryURL string) (*awid.IDChainEvidence, error) {
	status := awid.NewIDStatusClient(registry, resolver)
	status.Route = func(context.Context, string) (string, error) { return registryURL, nil }
	subject := awid.IDChainSubject{ID: p.record.StableID, DIDKey: p.record.DIDKey}
	evidence := status.IDChainEvidence(ctx, p.chain.Bundle, subject, p.record.Domain)
	verdict := awid.VerifyIDChain(p.chain.Bundle, subject, evidence, p.record.Domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid || verdict.Kind == nil || *verdict.Kind != "human" {
		return nil, fmt.Errorf("human %s cannot issue now: %s", p.record.StableID, verdict.Reason)
	}
	return evidence, nil
}

type agentChainStep struct {
	parent      *humanParent
	agentID     string
	agentKey    ed25519.PrivateKey
	domain      string
	registryURL string
	identityDir string
	registry    *awid.RegistryClient
	resolver    awid.TXTResolver
	keychain    awid.HumanKeyStore
	prompt      awid.PassphrasePrompt
	now         time.Time
}

// install issues, registers and installs the agent's chain. A certificate
// the human already issued to this agent is released again instead of a
// second one.
func (s agentChainStep) install(ctx context.Context) (map[string]any, error) {
	issuance := awconfig.IDIssuanceFileStore{Dir: awconfig.IdentityIssuanceDir(s.parent.dir)}
	entry, err := issuance.EntryForSubject(s.agentID)
	if err != nil {
		return nil, err
	}
	parentChain := s.parent.chain.Bundle["certificates"].([]any)
	var bundle map[string]any
	if entry != nil {
		bundle = map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": append(append([]any{}, parentChain...), entry.Signed)}
	} else {
		evidence, err := s.parent.evidence(ctx, s.registry, s.resolver, s.registryURL)
		if err != nil {
			return nil, err
		}
		child := awid.IDChild{ID: s.agentID, Domain: s.domain, Parent: map[string]any{"kind": "identity", "id": s.parent.record.StableID}, Kind: "agent"}
		sign := awid.HumanSigner(s.keychain, s.parent.record.StableID, "issue the certificate of agent "+s.agentID, s.prompt)
		if bundle, err = awid.IssueIDChild(issuance, child, parentChain, evidence, sign, s.now); err != nil {
			return nil, fmt.Errorf("issue the certificate of %s: %w", s.agentID, err)
		}
	}
	call, cancel := commandAPIContext(nil, ctx)
	_, err = s.registry.RegisterIDCertificateAt(call, s.registryURL, bundle, awid.KeySigner(s.agentKey), nil, nil)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("register the certificate of %s: %w", s.agentID, err)
	}
	if err := awconfig.SaveInstalledIDChain(s.identityDir, bundle); err != nil {
		return nil, err
	}
	return bundle, nil
}

// resumeIDCreateChain finishes the chain step of an agent this command
// already created: the identity at identityPath, named address, still
// without an installed chain.
func resumeIDCreateChain(ctx context.Context, opts idCreateOptions, parent *humanParent, identityPath, signingKeyPath, address string) (idCreateOutput, error) {
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		return idCreateOutput{}, err
	}
	if identity.Address != address {
		return idCreateOutput{}, usageError("standalone identity already exists at %s for %s", identityPath, identity.Address)
	}
	identityDir := filepath.Dir(identityPath)
	if installed, err := awconfig.LoadInstalledIDChain(identityDir); err != nil {
		return idCreateOutput{}, err
	} else if installed != nil {
		return idCreateOutput{}, usageError("%s already has its chain installed", identity.Address)
	}
	key, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return idCreateOutput{}, err
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return idCreateOutput{}, err
	}
	step := agentChainStep{
		parent: parent, agentID: identity.StableID, agentKey: key, domain: parent.record.Domain,
		registryURL: identity.RegistryURL, identityDir: identityDir, registry: registry, resolver: opts.TXTResolver,
		keychain: opts.Keychain, prompt: opts.Prompt, now: idCreateNow(opts)(),
	}
	if _, err := step.install(ctx); err != nil {
		return idCreateOutput{}, err
	}
	return idCreateOutput{
		Status:         "chain_installed",
		Address:        identity.Address,
		DIDAW:          identity.StableID,
		DIDKey:         identity.DID,
		IdentityPath:   identityPath,
		SigningKeyPath: signingKeyPath,
		RegistryStatus: identity.RegistryStatus,
		RegistryURL:    identity.RegistryURL,
		ParentHuman:    parent.record.StableID,
	}, nil
}

func idCreateNow(opts idCreateOptions) func() time.Time {
	if opts.Now != nil {
		return opts.Now
	}
	return time.Now
}

// prepareIDCreateParent checks, before any identity exists, that the named
// human can issue and that a human is at the terminal to sign as it.
func prepareIDCreateParent(opts idCreateOptions, domain string) (*humanParent, error) {
	id := strings.TrimSpace(opts.ParentHuman)
	if id == "" {
		return nil, nil
	}
	if opts.HumanAtTerminal == nil {
		return nil, errors.New("internal error: no terminal check for --parent-human")
	}
	if err := opts.HumanAtTerminal(); err != nil {
		return nil, fmt.Errorf("--parent-human signs as %s: %w", id, err)
	}
	return loadHumanParent(domain, id)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
