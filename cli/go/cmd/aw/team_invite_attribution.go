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

func identityID(identity *awconfig.ResolvedIdentity) string {
	if identity.StableID != "" {
		return identity.StableID
	}
	return identity.DID
}

// An explicit exchange participant is independent of the CLI's selected actor.
func resolveIDExchangeIdentity(wd, home string) (*awconfig.ResolvedIdentity, error) {
	if home == "" {
		return resolveIdentityForDir(wd)
	}
	identity, err := awconfig.ResolveIdentityFromHome(wd, home)
	if errors.Is(err, os.ErrNotExist) {
		identity, err = resolveCertificateIdentityAtHome(wd, home)
		if err == nil && identity.IdentityScope != awid.IdentityModeLocal {
			return nil, errors.New("global exchange identity is missing identity.yaml")
		}
	}
	if err != nil {
		return nil, err
	}
	identity.ExternalIdentityHome = true
	return identity, validateResolvedIdentity(identity)
}

// identityKeyRoute reads the identity's key route at registryURL, or at its
// own registry when registryURL is empty. Enrollment is a key-route fact,
// independent of namespace tree status. Read it freshly: an old response
// without id_tree is unknown, not legacy.
func identityKeyRoute(ctx context.Context, identity *awconfig.ResolvedIdentity, registryURL string) (*awid.DidKeyResolution, error) {
	registry, err := resolveIdentityRegistryClient(identity)
	if err != nil {
		return nil, err
	}
	if registryURL == "" {
		registryURL = registry.DefaultRegistryURL
	}
	return registry.ResolveKeyAt(ctx, registryURL, identity.StableID)
}

// Membership routing never replaces an issuer's own home registry. With no
// saved pin, the operation route can fill the same namespace's missing routing
// information, subject to its independently discovered registry constraint.
func teamInviteIssuerRegistry(ctx context.Context, opts idChildOptions, identity *awconfig.ResolvedIdentity, domain string) (string, error) {
	if own := strings.TrimSpace(identity.RegistryURL); own != "" {
		return own, nil
	}
	if selected := strings.TrimSpace(opts.RegistryURL); selected != "" {
		return selected, nil
	}
	if fallback := strings.TrimSpace(opts.TeamRegistryURL); fallback != "" && domain != "" && domain == opts.TeamRegistryDomain {
		authority, err := awid.DiscoverAuthoritativeRegistry(ctx, opts.TXTResolver, domain)
		if err != nil {
			return "", err
		}
		return domainRegistryURL(authority, fallback)
	}
	registry, err := resolveIdentityRegistryClient(identity)
	if err != nil {
		return "", err
	}
	if opts.TXTResolver != nil {
		registry.Resolver.DNSResolver = opts.TXTResolver
	}
	// An installed chain fixes the issuer namespace independently of any
	// address or team membership. The selector does not mutate identity state.
	own := *identity
	own.Domain = domain
	return currentIdentityRegistryURL(ctx, &own, registry)
}

// No chain is the legacy path only when current evidence establishes absence.
// A team key is never an ID-parent credential.
func prepareTeamInviteIDChild(ctx context.Context, opts idChildOptions) (*awconfig.TeamInviteIDChild, error) {
	identity, err := resolveIDExchangeIdentity(opts.WorkingDir, opts.IdentityHome)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	home := filepath.Dir(identity.SigningKeyPath)
	chain, err := awconfig.LoadInstalledIDChain(home)
	if err != nil {
		return nil, err
	}
	if chain == nil && identity.StableID == "" {
		return nil, nil
	}
	domain := identity.Domain
	if chain != nil {
		certificates := chain.Bundle["certificates"].([]any)
		domain = certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)["domain"].(string)
	}
	opts.RegistryURL, err = teamInviteIssuerRegistry(ctx, opts, identity, domain)
	if err != nil {
		return nil, fmt.Errorf("inviter cannot select its identity registry: %w", err)
	}
	if chain == nil {
		resolution, err := identityKeyRoute(ctx, identity, opts.RegistryURL)
		if err != nil {
			return nil, fmt.Errorf("inviter cannot issue: evidence_unavailable; check the inviter's identity registry connection and retry: %w", err)
		}
		if resolution.DIDAW != identity.StableID || resolution.CurrentDIDKey != identity.DID {
			return nil, fmt.Errorf("inviter key is not current; restore the identity's current signing key before inviting")
		}
		enrollment := resolution.IDTreeEnrollment(time.Now())
		switch enrollment.State {
		case "not_enrolled":
			return nil, nil
		case "enrolled":
			return nil, fmt.Errorf("inviter cannot issue: install this identity's ID chain first")
		default:
			return nil, fmt.Errorf("inviter cannot issue: %w; check or upgrade the inviter's identity registry, then retry", &awid.IDCertificateError{Code: "evidence_unavailable"})
		}
	}
	opts.IdentityHome = home
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := checkSelectedTeamInviteIssuer(ctx, issuer); err != nil {
		return nil, err
	}
	out, err := executeIDChildInvite(ctx, opts, "agent", "agent spawn", 7*24*time.Hour)
	if err != nil {
		return nil, err
	}
	inv, err := issuer.invitations.Invitation(out.InvitationID)
	if err != nil {
		return nil, err
	}
	inv.Purpose = "agent spawn"
	if err := issuer.invitations.PutInvitation(inv); err != nil {
		return nil, err
	}
	return &awconfig.TeamInviteIDChild{InvitationID: out.InvitationID, Parent: out.Parent["id"].(string), Domain: out.Domain, IssuerHome: home, RegistryURL: issuer.registryURL}, nil
}

func checkSelectedTeamInviteIssuer(ctx context.Context, issuer *selectedChildIssuer) error {
	identity, err := resolveIDExchangeIdentity("", filepath.Dir(issuer.invitations.Dir))
	if err != nil {
		return err
	}
	evidence, err := issuer.evidence(ctx, "", "")
	if err != nil {
		return err
	}
	bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": issuer.parentChain}
	verdict := awid.VerifyIDChain(bundle, awid.IDChainSubject{ID: identityID(identity), DIDKey: identity.DID}, evidence, issuer.domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid || verdict.Kind == nil || *verdict.Kind != "agent" {
		if verdict.Reason == "evidence_unavailable" {
			return fmt.Errorf("inviter cannot issue: %w; check the inviter's namespace DNS and identity registry, then retry", &awid.IDCertificateError{Code: verdict.Reason})
		}
		return fmt.Errorf("inviter cannot issue: %s", verdict.Reason)
	}
	return nil
}

func linkedTeamInviteIssuer(ctx context.Context, link *awconfig.TeamInviteIDChild) (idChildOptions, *selectedChildIssuer, error) {
	opts := idChildOptions{IdentityHome: link.IssuerHome, TeamRegistryURL: link.RegistryURL, TeamRegistryDomain: link.Domain, Now: time.Now}
	identity, err := resolveIDExchangeIdentity("", link.IssuerHome)
	if err != nil {
		return opts, nil, err
	}
	opts.RegistryURL, err = teamInviteIssuerRegistry(ctx, opts, identity, link.Domain)
	if err != nil {
		return opts, nil, err
	}
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return opts, nil, err
	}
	if issuer.domain != link.Domain || issuer.parent["id"] != link.Parent {
		return opts, nil, fmt.Errorf("inviter no longer matches the linked ID parent")
	}
	return opts, issuer, nil
}

func checkTeamInviteIssuer(ctx context.Context, link *awconfig.TeamInviteIDChild) error {
	_, issuer, err := linkedTeamInviteIssuer(ctx, link)
	if err != nil {
		return err
	}
	return checkSelectedTeamInviteIssuer(ctx, issuer)
}

// Complete the existing file exchange; records remain at both ends until done.
func completeTeamInviteIDChild(ctx context.Context, invite *awconfig.TeamInvite, wd, home string) error {
	link := invite.IDChild
	childOpts := idParentOptions{WorkingDir: wd, IdentityHome: home, Domain: link.Domain}
	outgoing, err := (awconfig.IDRequestFileStore{Dir: awconfig.IdentityRequestsDir(home)}).ForInvitation(link.InvitationID)
	if err != nil {
		return err
	}
	var raw []byte
	if outgoing == nil {
		_, raw, err = executeIDParentRequest(childOpts, link.InvitationID, link.Parent, false)
		if err != nil {
			return err
		}
	} else {
		raw = []byte(outgoing.Request)
	}
	issuerOpts, issuer, err := linkedTeamInviteIssuer(ctx, link)
	if err != nil {
		return err
	}
	received, err := executeIDChildReceive(ctx, issuerOpts, raw)
	if err != nil {
		return err
	}
	response, err := executeIDChildApprove(ctx, issuerOpts, received.RequestID)
	if err != nil {
		return err
	}
	childOpts.RegistryURL = issuer.registryURL
	_, err = executeIDParentImport(ctx, childOpts, response)
	return err
}

// Hosted roster provisioning has both identity homes, unlike an ordinary
// cross-machine accept. Use only the locally selected parent named by the
// retained hosted preview, then run the same request/approve/import exchange.
func completeHostedProvisioningIDChild(ctx context.Context, anchorDir, issuerHome, childDir, childHome string) error {
	state, err := loadHostedInviteCreation(filepath.Join(childHome, hostedInviteRecoveryFile))
	if err != nil {
		return err
	}
	if state == nil || state.Tree.Mode != "self_custodial" || state.Tree.Parent["kind"] != "identity" {
		return errors.New("hosted child has no pinned native issuer")
	}
	identity, err := resolveIDExchangeIdentity(anchorDir, issuerHome)
	if err != nil {
		return err
	}
	if identityID(identity) != state.Tree.Parent["id"] {
		return errors.New("hosted child issuer differs from the selected roster parent")
	}
	link, err := prepareTeamInviteIDChild(ctx, idChildOptions{WorkingDir: anchorDir, IdentityHome: issuerHome, Now: time.Now})
	if err != nil {
		return err
	}
	if link == nil || link.Parent != state.Tree.Parent["id"] || link.Domain != state.Tree.Domain {
		return errors.New("hosted child issuer binding differs from the selected roster parent chain")
	}
	return completeTeamInviteIDChild(ctx, &awconfig.TeamInvite{IDChild: link}, childDir, childHome)
}

// The caller owns both homes and explicitly provisions a new agent. Ordinary
// invite accept never guesses where another participant's signer might live.
func acceptProvisionedTeamInvite(anchorDir, issuerHome, childDir, token string, opts teamAcceptInviteOptions) (*acceptedTeamInvite, error) {
	accepted, err := acceptTeamInviteWithDetails(childDir, token, opts)
	var pending *hostedInviteSignaturePendingError
	if !errors.As(err, &pending) {
		return accepted, err
	}
	ctx, cancel := commandAPIContext(nil)
	exchangeErr := completeHostedProvisioningIDChild(ctx, anchorDir, issuerHome, childDir, opts.IdentityHome)
	cancel()
	if exchangeErr != nil {
		return nil, &hostedInviteSignaturePendingError{err: fmt.Errorf("native agent signature pending in %s; child key and request retained: %w", childDir, exchangeErr)}
	}
	// Resume with the original child key, request UUID and successful preview.
	// No Cloud acceptance was sent while the native signature was pending.
	return acceptTeamInviteWithDetails(childDir, token, opts)
}

// Reserve a fresh recipient before minting its key. A prepared identity joins
// membership-only; only this acceptance's own recipient resumes issuance.
func bindTeamInviteIDChild(ctx context.Context, invite *awconfig.TeamInvite, home string) (bool, error) {
	link := invite.IDChild
	if link.ChildHome != "" {
		if filepath.Clean(home) != link.ChildHome {
			return false, fmt.Errorf("ID issuance is pending in the original recipient identity home")
		}
		if link.ChildDIDKey != "" && !teamInviteChildKeyMatches(link, home) {
			return false, fmt.Errorf("invite recipient key changed or is missing; restore the original identity")
		}
	} else {
		for _, name := range []string{"identity.yaml", "signing.key"} {
			if _, err := os.Stat(filepath.Join(home, name)); err == nil {
				return false, nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
		}
	}
	if err := checkTeamInviteIssuer(ctx, link); err != nil {
		return false, err
	}
	link.ChildHome = filepath.Clean(home)
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		return false, err
	}
	return true, nil
}

func teamInviteChildKeyMatches(link *awconfig.TeamInviteIDChild, home string) bool {
	key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	if err != nil {
		return false
	}
	return awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) == link.ChildDIDKey
}

func canResumeTeamInviteIDChild(token, home string) bool {
	decoded, err := awconfig.DecodeInviteToken(token)
	if err != nil {
		return false
	}
	invite, err := awconfig.LoadTeamInvite(decoded.InviteID)
	if err != nil || invite.Secret != decoded.Secret || invite.IDChild == nil {
		return false
	}
	link := invite.IDChild
	return link.ChildHome == filepath.Clean(home) && link.ChildDIDKey != "" && teamInviteChildKeyMatches(link, home)
}
