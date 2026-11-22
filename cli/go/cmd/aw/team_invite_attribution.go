package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
			return nil, missingGlobalIdentityFile()
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
	registry, err := resolveIdentityRegistryClient(identity)
	if err != nil {
		return "", err
	}
	if opts.TXTResolver != nil {
		registry.Resolver.DNSResolver = opts.TXTResolver
	}
	return resolveRegistryAuthority(ctx, registryAuthorityRequest{
		Kind: registryInviteIssuerRoute, Registry: registry, Identity: identity, Domain: domain, Override: opts.RegistryURL,
		TXTResolver: opts.TXTResolver, TeamRegistry: opts.TeamRegistryURL, TeamDomain: opts.TeamRegistryDomain,
	})
}

// A local did:key can be chainless: it has no portable enrollment witness.
// A global did:aw needs authoritative no-enrollment evidence even when only
// selecting an invite condition. Present unreadable/malformed files refuse.
// A team key is never an ID-parent credential.
func prepareTeamInviteIDChild(ctx context.Context, opts idChildOptions) (*awconfig.TeamInviteIDChild, error) {
	link, _, err := prepareTeamInviteAuthority(ctx, teamInviteAuthorityRequest{Issuer: opts, Child: inviteCreatesChild})
	return link, err
}

type teamInviteChildPolicy uint8

const (
	inviteMembershipOnly teamInviteChildPolicy = iota
	inviteCreatesChild
)

type teamInviteAuthorityRequest struct {
	Issuer    idChildOptions
	Child     teamInviteChildPolicy
	ForHuman  *string
	ExpiresAt time.Time
}

func prepareTeamInviteAuthority(ctx context.Context, input teamInviteAuthorityRequest) (*awconfig.TeamInviteIDChild, *string, error) {
	if input.Child != inviteMembershipOnly && input.Child != inviteCreatesChild {
		return nil, nil, errors.New("unknown invite parentage policy")
	}
	opts, requested := input.Issuer, input.ForHuman
	identity, err := resolveIDExchangeIdentity(opts.WorkingDir, opts.IdentityHome)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	home := filepath.Dir(identity.SigningKeyPath)
	chain, err := awconfig.LoadInstalledIDChain(home)
	if err != nil {
		return nil, nil, err
	}
	if chain == nil && identity.StableID == "" {
		return nil, nil, nil
	}
	domain := identity.Domain
	if chain != nil {
		leaf, err := chain.Leaf()
		if err != nil {
			return nil, nil, err
		}
		domain = leaf.Domain()
	}
	opts.RegistryURL, err = teamInviteIssuerRegistry(ctx, opts, identity, domain)
	if err != nil {
		return nil, nil, fmt.Errorf("inviter cannot select its identity registry: %w", err)
	}
	if chain == nil {
		resolution, err := identityKeyRoute(ctx, identity, opts.RegistryURL)
		if err != nil {
			return nil, nil, fmt.Errorf("inviter cannot issue: evidence_unavailable; check the inviter's identity registry connection and retry: %w", err)
		}
		if resolution.DIDAW != identity.StableID || resolution.CurrentDIDKey != identity.DID {
			return nil, nil, fmt.Errorf("inviter key is not current; restore the identity's current signing key before inviting")
		}
		enrollment := resolution.IDTreeEnrollment(time.Now())
		switch enrollment.State {
		case "not_enrolled":
			return nil, nil, nil
		case "enrolled":
			return nil, nil, fmt.Errorf("inviter cannot issue: install this identity's ID chain first")
		default:
			return nil, nil, fmt.Errorf("inviter cannot issue: %w; check or upgrade the inviter's identity registry, then retry", &awid.IDCertificateError{Code: "evidence_unavailable"})
		}
	}
	opts.IdentityHome = home
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	defer issuer.close()
	verdict, err := selectedTeamInviteAuthority(ctx, issuer)
	if err != nil {
		return nil, nil, err
	}
	if input.Child == inviteMembershipOnly || (requested != nil && (verdict.HumanID == nil || *requested != *verdict.HumanID)) {
		return nil, verdict.HumanID, nil
	}
	expiresAfter := 7 * 24 * time.Hour
	if !input.ExpiresAt.IsZero() {
		now := time.Now()
		if opts.Now != nil {
			now = opts.Now()
		}
		expiresAfter = input.ExpiresAt.Sub(now)
		if expiresAfter <= 0 {
			return nil, nil, awconfig.ErrTeamInviteLifetime
		}
		opts.Now = func() time.Time { return now }
	}
	out, err := executeIDChildInvite(ctx, opts, "agent", "agent spawn", expiresAfter)
	if err != nil {
		return nil, nil, err
	}
	inv, err := issuer.invitations.Invitation(out.InvitationID)
	if err != nil {
		return nil, nil, err
	}
	inv.Purpose = "agent spawn"
	if err := issuer.invitations.PutInvitation(inv); err != nil {
		return nil, nil, err
	}
	parentID, validParent := out.Parent["id"].(string)
	if !validParent || parentID == "" {
		return nil, nil, errors.New("child invitation has no issuer ID; retain its record and restore the issuer's original chain before retrying")
	}
	return &awconfig.TeamInviteIDChild{InvitationID: out.InvitationID, Parent: parentID, Domain: out.Domain, IssuerHome: home, RegistryURL: issuer.registryURL}, verdict.HumanID, nil
}

func checkSelectedTeamInviteIssuer(ctx context.Context, issuer *selectedChildIssuer) error {
	_, err := selectedTeamInviteAuthority(ctx, issuer)
	return err
}

func selectedTeamInviteAuthority(ctx context.Context, issuer *selectedChildIssuer) (awid.IDChainResult, error) {
	identity, err := resolveIDExchangeIdentity("", filepath.Dir(issuer.invitations.Dir))
	if err != nil {
		return awid.IDChainResult{}, err
	}
	evidence, err := issuer.evidence(ctx, "", "")
	if err != nil {
		return awid.IDChainResult{}, err
	}
	bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": issuer.parentChain}
	verdict := awid.VerifyIDChain(bundle, awid.IDChainSubject{ID: identityID(identity), DIDKey: identity.DID}, evidence, issuer.domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid || verdict.Kind == nil || *verdict.Kind != "agent" {
		if verdict.Reason == "evidence_unavailable" {
			return awid.IDChainResult{}, fmt.Errorf("inviter cannot issue: %w; check the inviter's namespace DNS and identity registry, then retry", &awid.IDCertificateError{Code: verdict.Reason})
		}
		return awid.IDChainResult{}, fmt.Errorf("inviter cannot issue: %s", verdict.Reason)
	}
	return verdict, nil
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
		issuer.close()
		return opts, nil, fmt.Errorf("inviter no longer matches the linked ID parent")
	}
	return opts, issuer, nil
}

func checkTeamInviteIssuer(ctx context.Context, link *awconfig.TeamInviteIDChild) error {
	_, issuer, err := linkedTeamInviteIssuer(ctx, link)
	if err != nil {
		return err
	}
	defer issuer.close()
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
	defer issuer.close()
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
	accepted, err := acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
		WorkingDir: childDir,
		Token:      token,
		Options:    opts,
	})
	var pending *hostedInviteSignaturePendingError
	if !errors.As(err, &pending) {
		return accepted, err
	}
	// A current local link owns its retained exchange. Do not replace that
	// invitation/request with the compatibility completion for older invites.
	if _, linkErr := awconfig.LoadTeamInvite(hostedTeamInviteRecordID(token)); linkErr == nil {
		return nil, err
	} else if !errors.Is(linkErr, os.ErrNotExist) {
		return nil, linkErr
	}
	ctx, cancel := commandAPIContext(nil)
	exchangeErr := completeHostedProvisioningIDChild(ctx, anchorDir, issuerHome, childDir, opts.IdentityHome)
	cancel()
	if exchangeErr != nil {
		return nil, &hostedInviteSignaturePendingError{err: fmt.Errorf("native agent signature pending in %s; child key and request retained: %w", childDir, exchangeErr)}
	}
	// Resume with the original child key, request UUID and successful preview.
	// No Cloud acceptance was sent while the native signature was pending.
	return acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
		WorkingDir: childDir,
		Token:      token,
		Options:    opts,
	})
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
				fmt.Fprintln(os.Stderr, "Joining membership only; this existing identity keeps its parentage.")
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
