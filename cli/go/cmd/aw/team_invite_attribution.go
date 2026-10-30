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
	home := filepath.Dir(identity.IdentityPath)
	chain, err := awconfig.LoadInstalledIDChain(home)
	if err != nil {
		return nil, err
	}
	if chain == nil {
		if identity.StableID == "" {
			return nil, nil
		}
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
	return &awconfig.TeamInviteIDChild{InvitationID: out.InvitationID, Parent: out.Parent["id"].(string), Domain: out.Domain, IssuerHome: home}, nil
}

func checkSelectedTeamInviteIssuer(ctx context.Context, issuer *selectedChildIssuer) error {
	identity, err := awconfig.ResolveIdentityFromHome("", filepath.Dir(issuer.invitations.Dir))
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
	opts := idChildOptions{IdentityHome: link.IssuerHome, Now: time.Now}
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
	issuerOpts, _, err := linkedTeamInviteIssuer(ctx, link)
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
	_, err = executeIDParentImport(ctx, childOpts, response)
	return err
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
