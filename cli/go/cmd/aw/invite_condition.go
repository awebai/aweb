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
	"github.com/spf13/cobra"
)

// Verify the presented identity in its own namespace, independently of the team
// it is joining. All signature, ancestry and current-status rules are SDK rules.
func verifyInviteMembership(ctx context.Context, bundle map[string]any, subject awid.IDChainSubject, required *string, registry *awid.RegistryClient, resolver awid.TXTResolver) (*awid.IDChainResult, error) {
	if bundle == nil {
		if required != nil {
			return nil, fmt.Errorf("%w: this invite requires a chain to %s; obtain it from your own creator using aw id child invite, aw id parent request --domain <creator-domain>, and aw id parent import --domain <creator-domain>, then retry this join; on this machine use --parent HOME", &awid.IDCertificateError{Code: "human_required"}, *required)
		}
		return nil, nil
	}
	plan, err := awid.IDStatusRequest(bundle, subject, "")
	if err != nil {
		return nil, err
	}
	domain := plan["domain"].(string)
	_, origin, err := childIssuerRegistry(ctx, idChildOptions{TXTResolver: resolver}, domain)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", &awid.IDCertificateError{Code: "evidence_unavailable"}, err)
	}
	if registry == nil {
		registry, err = newConfiguredRegistryClient(nil)
		if err != nil {
			return nil, err
		}
	}
	evidence := idStatusAt(registry, resolver, origin).IDChainEvidence(ctx, bundle, subject, domain)
	verdict := awid.VerifyIDChain(bundle, subject, evidence, domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid {
		return nil, &awid.IDCertificateError{Code: verdict.Reason}
	}
	if verdict.Kind == nil || *verdict.Kind != "agent" {
		return nil, &awid.IDCertificateError{Code: "wrong_kind"}
	}
	if err := checkInviteHuman(&verdict, required); err != nil {
		return nil, err
	}
	return &verdict, nil
}

func checkInviteHuman(verdict *awid.IDChainResult, required *string) error {
	if required != nil && (verdict == nil || verdict.Outcome != "nearest_human" || verdict.HumanID == nil || *verdict.HumanID != *required) {
		return &awid.IDCertificateError{Code: "human_mismatch"}
	}
	return nil
}

func validateInviteHuman(value string) error {
	if !strings.HasPrefix(value, "did:aw:") || len(value) <= len("did:aw:") || strings.TrimSpace(value) != value || strings.ContainsAny(value, " /\t\n\r") {
		return usageError("--for-human requires a did:aw person ID")
	}
	return nil
}

// A prepared local child can acquire its first membership without manufacturing
// a pending hosted-creation marker. Completed or grant homes remain distinct.
func unjoinedChainSigningKey(home string) (ed25519.PrivateKey, error) {
	for _, name := range []string{"grant.yaml", "teams.yaml", "workspace.yaml"} {
		if _, err := os.Stat(filepath.Join(home, name)); err == nil {
			return nil, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	chain, err := awconfig.LoadInstalledIDChain(home)
	if err != nil || chain == nil {
		return nil, err
	}
	key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	if err != nil {
		return nil, err
	}
	identityPath := filepath.Join(home, "identity.yaml")
	if identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath); err == nil {
		if identity.IdentityScope != awid.IdentityModeLocal || identity.DID != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) || identity.Custody != awid.CustodySelf {
			return nil, usageError("prepared local chain does not match identity.yaml")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return key, nil
}

func requestedInviteHuman(values []string) (*string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, usageError("one --for-human value is required")
	}
	if err := validateInviteHuman(values[0]); err != nil {
		return nil, err
	}
	value := values[0]
	return &value, nil
}

// --parent names an explicit local creator. The private invitation and child
// request are retained so a failed join resumes with that same key and parent.
func completeExplicitInviteParent(ctx context.Context, wd, home, token, parentHome string) error {
	parentHome, err := filepath.Abs(parentHome)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(parentHome, "signing.key")); errors.Is(err, os.ErrNotExist) {
		parentHome = filepath.Join(parentHome, ".aw")
	}
	recordID := "creator-" + strings.TrimPrefix(hostedTeamInviteRecordID(token), "hosted-")
	invite, err := awconfig.LoadTeamInvite(recordID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if invite == nil {
		installed, err := awconfig.LoadInstalledIDChain(home)
		if err != nil {
			return err
		}
		if installed != nil {
			return usageError("--parent creates a fresh child's first chain; this home already has one, so join without --parent")
		}
		link, err := prepareTeamInviteIDChild(ctx, idChildOptions{WorkingDir: parentHome, IdentityHome: parentHome, Now: time.Now})
		if err != nil {
			return err
		}
		if link == nil {
			return usageError("--parent must name a creator with a valid ID chain")
		}
		key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
		if err != nil {
			return err
		}
		link.ChildHome, link.ChildDIDKey = home, awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		invite = &awconfig.TeamInvite{InviteID: recordID, IDChild: link}
		if err := awconfig.SaveTeamInvite(invite); err != nil {
			return err
		}
	}
	if invite.IDChild == nil || invite.IDChild.IssuerHome != parentHome || invite.IDChild.ChildHome != home || !teamInviteChildKeyMatches(invite.IDChild, home) {
		return usageError("retry changed the selected creator, child home or key")
	}
	if err := prepareInviteChildIdentity(home); err != nil {
		return err
	}
	return completeTeamInviteIDChild(ctx, invite, wd, home)
}

func inviteParentFlag(cmd *cobra.Command) string {
	value, _ := cmd.Flags().GetString("parent")
	return strings.TrimSpace(value)
}

// Parent exchange is an identity-creation step, before any membership is signed.
func prepareInviteChildIdentity(home string) error {
	path := filepath.Join(home, "identity.yaml")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	if err != nil {
		return err
	}
	return awconfig.SaveWorktreeIdentityTo(path, &awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), IdentityScope: awid.IdentityModeLocal, Custody: awid.CustodySelf, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
}

func consumedInviteParent(token, parentHome string) {
	if parentHome == "" {
		return
	}
	id := "creator-" + strings.TrimPrefix(hostedTeamInviteRecordID(token), "hosted-")
	if err := awconfig.DeleteTeamInvite(id); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to delete consumed invite %s: %v\n", id, err)
	}
}
