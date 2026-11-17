package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const hostedInviteRecoveryFile = "hosted-invite-creation.json"

// This is a private local record key, never a second bearer token.
func hostedTeamInviteRecordID(token string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return "hosted-" + hex.EncodeToString(digest[:])
}

func localHostedInviteLink(token string, state *hostedInviteCreation) (*awconfig.TeamInvite, error) {
	invite, err := awconfig.LoadTeamInvite(hostedTeamInviteRecordID(token))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if invite.InviteID != hostedTeamInviteRecordID(token) || invite.IDChild == nil ||
		invite.IDChild.Parent != state.Tree.Parent["id"] || invite.IDChild.Domain != state.Tree.Domain ||
		awid.BuildTeamID(invite.Domain, invite.TeamName) != state.TeamID {
		return nil, errors.New("local hosted invite link differs from the pinned preview")
	}
	return invite, nil
}

func completeLocalHostedInvite(ctx context.Context, invite *awconfig.TeamInvite, state *hostedInviteCreation, wd, home string) error {
	link := invite.IDChild
	if link.ChildHome == "" {
		// Hosted acceptance has already retained this new key before preview.
		link.ChildHome, link.ChildDIDKey = home, state.DIDKey
	}
	if _, err := bindTeamInviteIDChild(ctx, invite, home); err != nil {
		return err
	}
	return completeTeamInviteIDChild(ctx, invite, wd, home)
}

// Only the recipe's explicit, retained local-agent home can make this transition.
func pendingHostedExchangeTarget(cmd *cobra.Command, home awconfig.IdentityHome) (bool, error) {
	if home.Source != awconfig.IdentityHomeFlag || (cmd != idParentRequestCmd && cmd != idParentImportCmd) || humanFlag != "" {
		return false, nil
	}
	for _, name := range []string{"grant.yaml", "identity.yaml", "teams.yaml", "workspace.yaml"} {
		if _, err := os.Lstat(filepath.Join(home.Root, name)); err == nil {
			return false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	_, err := pendingHostedInviteRequester(idParentOptions{WorkingDir: mustGetwd(), IdentityHome: home.Root, Domain: idParentDomain})
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// A local issuer link completes the exchange; a caller without that record
// retains the explicit request/import diagnostic and pending state.
type hostedInviteSignaturePendingError struct{ err error }

func (e *hostedInviteSignaturePendingError) Error() string { return e.err.Error() }
func (e *hostedInviteSignaturePendingError) Unwrap() error { return e.err }

type hostedInviteCreation struct {
	AcceptAttempted       *bool                 `json:"accept_attempted,omitempty"`
	ForHuman              *string               `json:"for_human,omitempty"`
	MembershipChain       map[string]any        `json:"membership_chain,omitempty"`
	IssuerCreationStarted bool                  `json:"issuer_creation_started,omitempty"`
	TokenHash             string                `json:"token_hash"`
	AwebURL               string                `json:"aweb_url"`
	Alias                 string                `json:"alias"`
	Address               string                `json:"address"`
	Scope                 string                `json:"scope"`
	NoAddress             bool                  `json:"no_address"`
	DIDKey                string                `json:"did_key"`
	StableID              string                `json:"stable_id"`
	InviteID              string                `json:"invite_id"`
	TeamID                string                `json:"team_id"`
	Tree                  *hostedIDTreeRecovery `json:"id_tree"`
	RequestReady          bool                  `json:"request_ready"`
	ResponseJSON          string                `json:"response_json,omitempty"`
}

func loadHostedInviteCreation(path string) (*hostedInviteCreation, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state hostedInviteCreation
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	if state.Tree == nil || !hostedIdentityTeamUUID.MatchString(state.Tree.RequestID) || state.TokenHash == "" || state.DIDKey == "" {
		return nil, errors.New("invalid hosted invite recovery")
	}
	return &state, nil
}

func (state *hostedInviteCreation) save(path string) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(path, raw)
}

func prepareHostedInviteCreation(ctx context.Context, prior *hostedInviteCreation, token, origin, alias, address string, noAddress bool, material workspaceTeamIdentityMaterial) (*hostedInviteCreation, error) {
	digest := sha256.Sum256([]byte(token))
	state := &hostedInviteCreation{AcceptAttempted: new(bool), TokenHash: hex.EncodeToString(digest[:]), AwebURL: origin, Alias: alias, Address: address, NoAddress: noAddress, Scope: material.IdentityScope, DIDKey: material.DIDKey, StableID: material.StableID}
	if prior != nil {
		if state.TokenHash != prior.TokenHash || state.AwebURL != prior.AwebURL || state.Alias != prior.Alias || state.Address != prior.Address || state.Scope != prior.Scope || state.NoAddress != prior.NoAddress || state.DIDKey != prior.DIDKey || state.StableID != prior.StableID {
			return nil, errors.New("hosted invite retry changed the original token, child key, scope or creation selection")
		}
		return prior, nil
	}
	// Preview is required. It is a possession-only read, independent of the
	// child's later signed acceptance and of any response-selected ancestry.
	_, wire, previewErr := readHostedInvitePreview(ctx, token, hostedJoinTokenEnvelope{AwebURL: origin})
	if previewErr != nil {
		return nil, withErrorCode(previewErr.Code, previewErr)
	}
	if !wire.IDTreePresent || !hostedIdentityTeamUUID.MatchString(wire.InviteID) {
		return nil, errors.New("hosted invite preview omitted its invitation ID or explicit ID-tree metadata")
	}
	state.InviteID, state.TeamID, state.ForHuman = wire.InviteID, wire.CanonicalTeamID, wire.ForHuman
	tree, err := newHostedIDTreeRecovery(hostedIdentityContext{})
	state.Tree = tree
	if err != nil {
		return nil, err
	}
	if inv := wire.CreationInvitation; inv != nil {
		name := alias
		if err := inv.Validate(); err != nil {
			return nil, err
		}
		if name != inv.Name || material.IdentityScope != inv.IdentityScope || wire.IDTree != nil {
			return nil, errors.New("creation invitation differs from requested child or conflicts with ID-tree issuer")
		}
		tree.Domain, tree.Parent, tree.InvitationID, tree.Mode = inv.Domain, inv.Parent, inv.ID, "host_managed"
		return state, nil
	}
	if wire.IDTree == nil {
		return state, nil
	}
	pinned := wire.IDTree
	if !hostedIdentityTeamUUID.MatchString(wire.InviteID) || pinned.V != 1 || pinned.ChildKind != "agent" || (pinned.Mode != "host_managed" && pinned.Mode != "self_custodial") || awconfig.NormalizeDomain(pinned.Domain) != pinned.Domain || pinned.Domain == "" {
		return nil, errors.New("invalid hosted invite issuer binding")
	}
	if _, err := awid.ExtractPublicKey(pinned.IssuerID); err != nil && !(strings.HasPrefix(pinned.IssuerID, "did:aw:") && len(pinned.IssuerID) > len("did:aw:") && strings.TrimSpace(pinned.IssuerID) == pinned.IssuerID) {
		return nil, errors.New("invalid hosted invite agent issuer ID")
	}

	state.Tree.Domain = pinned.Domain
	state.Tree.Parent = map[string]any{"kind": "identity", "id": pinned.IssuerID}
	state.Tree.Mode = pinned.Mode
	return state, nil
}

func (state *hostedInviteCreation) prepareRequest(root string, material workspaceTeamIdentityMaterial) (*awid.IDTreeCreationRequest, error) {
	if state.MembershipChain != nil {
		return nil, nil
	}
	if !state.IssuerCreationStarted {
		installed, err := awconfig.LoadInstalledIDChain(root)
		if err != nil {
			return nil, err
		}
		if installed != nil {
			state.MembershipChain = installed.Bundle
			return nil, nil
		}
	}
	if state.Tree.Domain == "" && state.ForHuman != nil {
		return nil, &hostedInviteSignaturePendingError{err: fmt.Errorf("this invite admits agents of %s; obtain a chain from your own creator first using aw id child invite, aw id parent request, and aw id parent import, then retry this join in the same home; on this machine use --parent HOME", *state.ForHuman)}
	}
	if material.IdentityScope == awid.IdentityModeGlobal && strings.HasPrefix(fmt.Sprint(state.Tree.Parent["id"]), "did:key:") {
		return nil, &awid.IDCertificateError{Code: "unregistered_parent"}
	}
	state.IssuerCreationStarted = true
	if state.Tree.Domain == "" {
		return nil, nil
	}
	if !state.RequestReady {
		installed, err := awconfig.LoadInstalledIDChain(root)
		if err != nil {
			return nil, err
		}
		if installed == nil && state.Tree.Mode == "self_custodial" {
			return nil, &hostedInviteSignaturePendingError{err: fmt.Errorf(`native agent signature pending for %s; its key and pending invite are retained in %s.
On parent %s, in its own identity home (requires jq for the JSON IDs):
  aw --json id child invite --kind agent --recipient %s > id-invitation.json
Transfer id-invitation.json to this child, then run:
  aw --identity-home %s id parent request --domain %s --parent %s --invitation-id "$(jq -r .invitation_id id-invitation.json)" --out id-request.json
Transfer id-request.json to the parent, then run there:
  aw --json id child receive id-request.json > id-received.json
  aw id child approve "$(jq -r .request_id id-received.json)" --out id-response.json
Transfer id-response.json back to this child, then run:
  aw --identity-home %s id parent import id-response.json
Finally retry your original invite command with the SAME token, name, scope and identity home (aw id team accept-invite or aw team join).`,
				material.DIDKey, root, state.Tree.Parent["id"], shellQuote(material.DIDKey), shellQuote(root), shellQuote(state.Tree.Domain), shellQuote(fmt.Sprint(state.Tree.Parent["id"])), shellQuote(root))}
		}
		if installed != nil {
			bundle := installed.Bundle
			if _, err := awid.EncodeIDChainHeader(bundle); err != nil {
				return nil, err
			}
			certificates := bundle["certificates"].([]any)
			leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
			subject := material.DIDKey
			if material.IdentityScope == awid.IdentityModeGlobal {
				subject = material.StableID
			}
			if leaf["id"] != subject || leaf["kind"] != "agent" || leaf["domain"] != state.Tree.Domain || !reflect.DeepEqual(leaf["parent"], state.Tree.Parent) {
				return nil, errors.New("installed child chain contradicts the pinned invite issuer; membership cannot reparent an identity")
			}
			state.Tree.NativeChainHeader, err = awid.EncodeIDChainHeader(bundle)
			if err != nil {
				return nil, err
			}
		}
		state.RequestReady = true
	}
	var bundle map[string]any
	if state.Tree.NativeChainHeader != "" {
		var err error
		bundle, err = awid.DecodeIDChainHeader(state.Tree.NativeChainHeader)
		if err != nil {
			return nil, err
		}
	}
	return state.Tree.request(bundle), nil
}

// A pending local invite already has its final child key, but no membership or
// identity file. Let the existing parent exchange use only that pinned agent.
func pendingHostedInviteRequester(opts idParentOptions) (*requester, error) {
	home, err := identityHomeForTarget(opts.WorkingDir, opts.IdentityHome)
	if err != nil {
		return nil, err
	}
	path, err := awconfig.IdentityHomePath(home, hostedInviteRecoveryFile)
	if err != nil {
		return nil, err
	}
	state, err := loadHostedInviteCreation(path)
	if err != nil {
		return nil, err
	}
	if state == nil || state.Scope != "local" || state.StableID != "" {
		return nil, os.ErrNotExist
	}
	independent := state.ForHuman != nil && state.Tree.Domain == ""
	domain := state.Tree.Domain
	expectedParent := state.Tree.Parent
	if independent {
		domain = opts.Domain
		expectedParent = nil
		if domain == "" {
			return nil, usageError("name your creator's --domain for this parent request or import")
		}
	} else if state.Tree.Mode != "self_custodial" || domain == "" || expectedParent["kind"] != "identity" {
		return nil, os.ErrNotExist
	}
	if !independent && opts.Domain != "" && opts.Domain != state.Tree.Domain {
		return nil, errors.New("parent request domain differs from the pending hosted invitation")
	}
	keyPath, err := awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return nil, err
	}
	key, err := awid.LoadSigningKey(keyPath)
	if err != nil {
		return nil, err
	}
	if awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != state.DIDKey {
		return nil, errors.New("pending hosted invite child key changed")
	}
	return &requester{id: state.DIDKey, didKey: state.DIDKey, domain: domain, kind: "agent", dir: home.Root, expectedParent: expectedParent, signer: func(string) awid.IDCertificateSigner { return awid.KeySigner(key) }}, nil
}

// A condition refusal grants no membership. It releases the operation selection,
// never the identity, signed ancestry, or a retained successful Cloud answer.
func releaseRefusedHostedInvite(recoveryPath, markerPath string, refusal error) error {
	definitive := awid.IDCertificateErrorCode(refusal) == "human_mismatch"
	status, hasStatus := awid.HTTPStatusCode(refusal)
	if hasStatus && status == http.StatusConflict && awid.RefusalCode(refusal) == "human_condition_mismatch" {
		definitive = true
	}
	if !definitive {
		return refusal
	}
	if err := discardHostedInviteAttempt(recoveryPath, markerPath); err != nil {
		return errors.Join(refusal, err)
	}
	return refusal
}

func discardHostedInviteAttempt(recoveryPath, markerPath string) error {
	if err := removeHostedAcceptPendingMarker(markerPath); err != nil {
		return fmt.Errorf("release refused invite marker: %w", err)
	}
	if err := os.Remove(recoveryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("release refused invite recovery: %w", err)
	}
	return nil
}
