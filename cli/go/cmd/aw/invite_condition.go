package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
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
		return nil, missingInviteHumanChain(required)
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

func missingInviteHumanChain(required *string) error {
	if required == nil {
		return nil
	}
	return fmt.Errorf("%w: this invite requires a chain to %s; obtain it from your own creator using aw id child invite, aw id parent request --domain <creator-domain>, and aw id parent import --domain <creator-domain>, then retry this join; on this machine use --parent HOME", &awid.IDCertificateError{Code: "human_required"}, *required)
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
	recordID, invite, err := loadTeamInviteParentRecord(token, home)
	if err != nil {
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

// The exchange belongs to one recipient home even when the hosted invite
// permits multiple children (docs/identity.md, explicit parent exchange).
func loadTeamInviteParentRecord(token, childHome string) (string, *awconfig.TeamInvite, error) {
	legacyID := "creator-" + strings.TrimPrefix(hostedTeamInviteRecordID(token), "hosted-")
	digest := sha256.Sum256([]byte(legacyID + "\x00" + filepath.Clean(childHome)))
	recordID := fmt.Sprintf("creator-%x", digest)
	invite, err := awconfig.LoadTeamInvite(recordID)
	if !errors.Is(err, os.ErrNotExist) {
		return recordID, invite, err
	}

	legacy, err := awconfig.LoadTeamInvite(legacyID)
	if errors.Is(err, os.ErrNotExist) {
		return recordID, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if legacy.IDChild == nil {
		return "", nil, errors.New("retained creator exchange has no child binding")
	}
	if legacy.IDChild.ChildHome == childHome {
		return legacyID, legacy, nil
	}
	return recordID, nil, nil
}

func consumeInviteParent(recordID string) error {
	if recordID == "" {
		return nil
	}
	return recordConsumedTeamInvite(recordID)
}

// recordConsumedTeamInvite retains the irreversible issuance consequence, with
// no remaining bearer secret, before the accepting operation reports success.
func recordConsumedTeamInvite(id string) error {
	if err := awconfig.ConsumeTeamInvite(awconfig.ConsumeTeamInviteInput{InviteID: id, Now: time.Now()}); err != nil {
		return fmt.Errorf("membership was issued, but recording consumed invite %s failed: %w; retain the identity home and reconcile this invite before retrying", id, err)
	}
	return nil
}

type issuedInvitePersistenceFailure struct {
	Cause       error
	Invite      *awconfig.TeamInvite
	Certificate *awid.TeamCertificate
	RegistryURL string
}

// An issued certificate outlives a failed recipient write. Recovery fetches that
// exact certificate with the retained member key (docs/awid-sot.md:128-132).
func issuedInvitePersistenceRefusal(failure issuedInvitePersistenceFailure) error {
	recovery := formatShellCommand([]string{
		"aw", "id", "team", "fetch-cert", "--namespace", failure.Invite.Domain,
		"--team", failure.Invite.TeamName, "--cert-id", failure.Certificate.CertificateID,
		"--registry", failure.RegistryURL,
	})
	return retainIdentityForRecovery(withErrorCode("certificate_persistence_incomplete", fmt.Errorf("membership certificate %s was issued but could not be saved: %w; retain the recipient key, repair its certificate path, and run `%s` from the same identity home", failure.Certificate.CertificateID, failure.Cause, recovery)))
}

func closeTeamInviteLock(lock io.Closer) {
	if err := lock.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close local invite lock: %v\n", err)
	}
}

func normalizeInviteParentHome(parent string) (string, error) {
	if parent == "" {
		return "", nil
	}
	home, err := filepath.Abs(parent)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(home, "signing.key")); errors.Is(err, os.ErrNotExist) {
		home = filepath.Join(home, ".aw")
	}
	return home, nil
}

func (s *hostedInviteCreation) selectParent(parent string) (string, error) {
	selected, err := normalizeInviteParentHome(parent)
	if err != nil {
		return "", err
	}
	if selected == "" && s.ParentSelected {
		return s.ParentHome, nil
	}
	if selected != s.ParentHome {
		if s.ResponseJSON != "" || s.AcceptAttempted == nil || *s.AcceptAttempted {
			return "", errors.New("cannot change parent after a possibly applied invite submission")
		}
		if s.ParentHome != "" {
			return "", errors.New("retry changed the selected creator")
		}
		// No request went to Cloud. The explicit creator now supplies parentage.
		s.IssuerCreationStarted = false
		s.MembershipOnly = false
		s.RequestReady = false
	}
	s.ParentHome, s.ParentSelected = selected, true
	return selected, nil
}
