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

// An agent created with --human-parent or --root-parent carries a chain from
// creation (docs/id-certificates.md §6, "Immediate init/spawn signs
// directly"). Its parent signs the agent's certificate and records it in its
// own issuance log before releasing it; the agent registers it with its own
// key proof. A human parent is named explicitly, never a human record found
// on disk; the root parent is this machine's namespace controller, and a
// root→agent chain means no human (§3).

// childIssuer is who signs a child's certificate: a human or agent on this
// machine, or the namespace root through this machine's controller.
type childIssuer struct {
	parent      map[string]any
	parentChain []any
	issuance    awconfig.IDIssuanceFileStore
	invitations awconfig.IDInvitationFileStore
	// signer signs for the issuer; description names the act a human's
	// passphrase prompt approves.
	signer func(description string) awid.IDCertificateSigner
	// evidence is current status for issuing to the child, refused when the
	// issuer cannot issue now.
	evidence func(ctx context.Context, childID, childDIDKey string) (*awid.IDChainEvidence, error)
	// human is the issuing human's did:aw; empty for the root.
	human string
}

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

// issuer signs as the human through its keychain key and terminal prompt,
// once its chain and key verify against fresh status from registryURL.
func (p *humanParent) issuer(keychain awid.HumanKeyStore, prompt awid.PassphrasePrompt, resolver awid.TXTResolver, registry *awid.RegistryClient, registryURL string) *childIssuer {
	return &childIssuer{
		parent:      map[string]any{"kind": "identity", "id": p.record.StableID},
		parentChain: p.chain.Bundle["certificates"].([]any),
		issuance:    awconfig.IDIssuanceFileStore{Dir: awconfig.IdentityIssuanceDir(p.dir)},
		invitations: awconfig.IDInvitationFileStore{Dir: awconfig.IdentityInvitationsDir(p.dir)},
		signer: func(description string) awid.IDCertificateSigner {
			return awid.HumanSigner(keychain, p.record.StableID, description, prompt)
		},
		evidence: func(ctx context.Context, _, _ string) (*awid.IDChainEvidence, error) {
			subject := awid.IDChainSubject{ID: p.record.StableID, DIDKey: p.record.DIDKey}
			evidence := idStatusAt(registry, resolver, registryURL).IDChainEvidence(ctx, p.chain.Bundle, subject, p.record.Domain)
			if err := humanCanIssue(p.record.StableID, awid.VerifyIDChain(p.chain.Bundle, subject, evidence, p.record.Domain)); err != nil {
				return nil, err
			}
			return evidence, nil
		},
		human: p.record.StableID,
	}
}

// humanCanIssue holds when id's own chain verifies now as a human's: a
// record under ~/.awid/humans whose chain names an agent issues nothing.
func humanCanIssue(id string, verdict awid.IDChainResult) error {
	if verdict.IdentityValid == nil || !*verdict.IdentityValid {
		return fmt.Errorf("human %s cannot issue now: %s", id, verdict.Reason)
	}
	if verdict.Kind == nil || *verdict.Kind != "human" {
		return fmt.Errorf("human %s cannot issue: its chain is not a human's", id)
	}
	return nil
}

// rootIssuer signs as the namespace root with this machine's controller key.
// Status is read for the agent itself: the namespace's open epoch decides
// the issuing key.
func rootIssuer(domain string, controllerKey ed25519.PrivateKey, registry *awid.RegistryClient, resolver awid.TXTResolver, registryURL string) (*childIssuer, error) {
	dir, err := awconfig.ControllerIssuanceDir(domain)
	if err != nil {
		return nil, err
	}
	invitations, err := awconfig.ControllerInvitationsDir(domain)
	if err != nil {
		return nil, err
	}
	return &childIssuer{
		parent:      map[string]any{"kind": "namespace", "id": domain},
		issuance:    awconfig.IDIssuanceFileStore{Dir: dir},
		invitations: awconfig.IDInvitationFileStore{Dir: invitations},
		signer:      func(string) awid.IDCertificateSigner { return awid.KeySigner(controllerKey) },
		evidence: func(ctx context.Context, childID, childDIDKey string) (*awid.IDChainEvidence, error) {
			return idStatusAt(registry, resolver, registryURL).IDChainEvidence(ctx, nil, awid.IDChainSubject{ID: childID, DIDKey: childDIDKey}, domain), nil
		},
	}, nil
}

// checkRootController checks this machine's controller against the domain's
// exact TXT or its delegate registry's witnessed child record.
func checkRootController(ctx context.Context, resolver awid.TXTResolver, domain, registryOverride string, controllerKey ed25519.PrivateKey) error {
	authority, err := awid.DiscoverAuthoritativeRegistry(ctx, resolver, domain)
	if err != nil {
		return fmt.Errorf("--root-parent: lookup %s: %w", awid.AWIDTXTName(domain), err)
	}
	registryURL, err := domainRegistryURL(authority, registryOverride)
	if err != nil {
		return err
	}
	controller, err := awid.NewAWIDRegistryClient(nil, resolver).IDNamespaceController(ctx, domain, registryURL, authority)
	if err != nil {
		return err
	}
	local := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	if strings.TrimSpace(controller) != local {
		if authority.Inherited {
			return fmt.Errorf("--root-parent: namespace controller %s for %s does not match this machine's controller %s", controller, domain, local)
		}
		return fmt.Errorf("--root-parent: DNS controller %s for %s does not match this machine's controller %s (publish %s naming it first; `aw id namespace check-txt --domain %s` checks it)", controller, domain, local, awid.AWIDTXTName(domain), domain)
	}
	return nil
}

func idStatusAt(registry *awid.RegistryClient, resolver awid.TXTResolver, registryURL string) *awid.IDStatusClient {
	status := awid.NewIDStatusClient(registry, resolver)
	status.Route = func(context.Context, string) (string, error) { return registryURL, nil }
	return status
}

type agentChainStep struct {
	issuer      *childIssuer
	agentID     string
	agentDIDKey string
	agentKey    ed25519.PrivateKey
	domain      string
	registryURL string
	identityDir string
	registry    *awid.RegistryClient
	now         time.Time
}

// issue reuses the issuer's original certificate for this child, or records
// its first certificate before returning it for registration.
func (s agentChainStep) issue(ctx context.Context) (map[string]any, error) {
	entry, err := s.issuer.issuance.EntryForSubject(s.agentID)
	if err != nil {
		return nil, err
	}
	var bundle map[string]any
	if entry != nil {
		bundle = map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": append(append([]any{}, s.issuer.parentChain...), entry.Signed)}
	} else {
		evidence, err := s.issuer.evidence(ctx, s.agentID, s.agentDIDKey)
		if err != nil {
			return nil, err
		}
		child := awid.IDChild{ID: s.agentID, Domain: s.domain, Parent: s.issuer.parent, Kind: "agent"}
		if bundle, err = awid.IssueIDChild(s.issuer.issuance, child, s.issuer.parentChain, evidence, s.issuer.signer("issue the certificate of "+s.agentID), s.now); err != nil {
			return nil, fmt.Errorf("issue the certificate of %s: %w", s.agentID, err)
		}
	}
	return bundle, nil
}

func (s agentChainStep) install(ctx context.Context) (map[string]any, error) {
	bundle, err := s.issue(ctx)
	if err != nil {
		return nil, err
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

// idCreateParent is the parent named on the command line, checked before
// any identity exists: a human that can sign at this terminal, or the root.
type idCreateParent struct {
	human *humanParent
	root  bool
}

func prepareIDCreateParent(opts idCreateOptions, domain string) (*idCreateParent, error) {
	human := strings.TrimSpace(opts.HumanParent)
	switch {
	case human != "" && opts.RootParent:
		return nil, usageError("--human-parent and --root-parent name different parents; choose one")
	case opts.RootParent:
		return &idCreateParent{root: true}, nil
	case human == "":
		return nil, nil
	}
	if opts.HumanAtTerminal == nil {
		return nil, errors.New("internal error: no terminal check for --human-parent")
	}
	if err := opts.HumanAtTerminal(); err != nil {
		return nil, fmt.Errorf("--human-parent signs as %s: %w", human, err)
	}
	parent, err := loadHumanParent(domain, human)
	if err != nil {
		return nil, err
	}
	return &idCreateParent{human: parent}, nil
}

// issuer is the parent's childIssuer; the root signs with controllerKey.
func (p *idCreateParent) issuer(opts idCreateOptions, domain string, controllerKey ed25519.PrivateKey, registry *awid.RegistryClient, registryURL string) (*childIssuer, error) {
	if p.root {
		return rootIssuer(domain, controllerKey, registry, opts.TXTResolver, registryURL)
	}
	return p.human.issuer(opts.Keychain, opts.Prompt, opts.TXTResolver, registry, registryURL), nil
}

// preflight refuses, before the agent exists, a parent that cannot issue,
// so a refused parent leaves no chainless agent.
func (p *idCreateParent) preflight(ctx context.Context, opts idCreateOptions, issuer *childIssuer, domain string, controllerKey ed25519.PrivateKey) error {
	if p.root {
		return checkRootController(ctx, opts.TXTResolver, domain, opts.RegistryURL, controllerKey)
	}
	_, err := issuer.evidence(ctx, "", "")
	return err
}

// resumeIDCreateChain finishes the chain step of an agent this command
// already created: the identity at identityPath, named address, still
// without an installed chain.
func resumeIDCreateChain(ctx context.Context, opts idCreateOptions, parent *idCreateParent, domain, identityPath, signingKeyPath, address string) (idCreateOutput, error) {
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
	var controllerKey ed25519.PrivateKey
	if parent.root {
		if controllerKey, err = awconfig.LoadControllerKey(domain); err != nil {
			return idCreateOutput{}, fmt.Errorf("load namespace controller key for %s: %w", domain, err)
		}
		if err := checkRootController(ctx, opts.TXTResolver, domain, opts.RegistryURL, controllerKey); err != nil {
			return idCreateOutput{}, err
		}
	}
	issuer, err := parent.issuer(opts, domain, controllerKey, registry, identity.RegistryURL)
	if err != nil {
		return idCreateOutput{}, err
	}
	step := agentChainStep{
		issuer: issuer, agentID: identity.StableID, agentDIDKey: identity.DID, agentKey: key, domain: domain,
		registryURL: identity.RegistryURL, identityDir: identityDir, registry: registry, now: idCreateNow(opts)(),
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
		HumanParent:    issuer.human,
		RootParent:     parent.root,
	}, nil
}

func idCreateNow(opts idCreateOptions) func() time.Time {
	if opts.Now != nil {
		return opts.Now
	}
	return time.Now
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
