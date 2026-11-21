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
	"io"
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
	if home.Source == awconfig.IdentityHomeFlag && cmd == teamFetchCertCmd && humanFlag == "" {
		state, err := loadHostedInviteCreation(filepath.Join(home.Root, hostedInviteRecoveryFile))
		if err != nil || state == nil {
			return false, err
		}
		if awid.BuildTeamID(teamFetchCertNamespace, teamFetchCertTeam) != state.TeamID || teamFetchCertID == "" {
			return false, nil
		}
		for _, name := range []string{"grant.yaml", "teams.yaml", "workspace.yaml"} {
			if _, err := os.Stat(filepath.Join(home.Root, name)); !errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
		}
		key, err := awid.LoadSigningKey(filepath.Join(home.Root, "signing.key"))
		return err == nil && awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) == state.DIDKey, err
	}

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
	MintedKey             *bool                 `json:"minted_key,omitempty"`
	ParentFromSource      *bool                 `json:"parent_from_source,omitempty"`
	MembershipOnly        bool                  `json:"membership_only"`
	ParentHome            string                `json:"parent_home,omitempty"`
	ParentSelected        bool                  `json:"parent_selected,omitempty"`
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
	raw, err := (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(path)}, Name: filepath.Base(path)}).Read()
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
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid hosted invite recovery JSON; retain the file for reconciliation")
	}
	if state.Tree == nil || !hostedIdentityTeamUUID.MatchString(state.Tree.RequestID) || state.TokenHash == "" || state.DIDKey == "" {
		return nil, errors.New("invalid hosted invite recovery")
	}
	// Stable 1.36.58 retained an issuer-creation selection before these facts
	// existed. An upgrade must replay it, including a native chain on disk.
	if state.MintedKey == nil && state.Tree.Domain != "" {
		state.IssuerCreationStarted = true
	}
	return &state, nil
}

func (state *hostedInviteCreation) save(path string) error {
	saved := *state
	response, err := hostedInviteInstallationResponse(state.ResponseJSON)
	if err != nil {
		return err
	}
	saved.ResponseJSON = response
	raw, err := json.Marshal(&saved)
	if err != nil {
		return err
	}
	return (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(path)}, Name: filepath.Base(path)}).Write(raw)
}

// hostedInviteInstallationResponse retains the installation evidence but no
// workspace API key: hosted invite acceptance acts with its own identity key.
// Raw fields keep forward-compatible response evidence intact.
func hostedInviteInstallationResponse(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return "", fmt.Errorf("read hosted invite installation response: %w", err)
	}
	if _, present := fields["api_key"]; !present {
		return raw, nil
	}
	delete(fields, "api_key")
	sanitized, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return string(sanitized), nil
}

func prepareHostedInviteCreation(ctx context.Context, prior *hostedInviteCreation, token, origin, alias, address string, noAddress bool, material workspaceTeamIdentityMaterial, mintedKey, parentFromSource bool, parentHome, recoveryPath string) (*hostedInviteCreation, error) {
	digest := sha256.Sum256([]byte(token))
	state := &hostedInviteCreation{MintedKey: &mintedKey, ParentFromSource: &parentFromSource, AcceptAttempted: new(bool), TokenHash: hex.EncodeToString(digest[:]), AwebURL: origin, Alias: alias, Address: address, NoAddress: noAddress, Scope: material.IdentityScope, DIDKey: material.DIDKey, StableID: material.StableID}
	if prior != nil {
		if parentFromSource && prior.MintedKey != nil && (prior.ParentFromSource == nil || !*prior.ParentFromSource) {
			return nil, errors.New("hosted invite retry changed the explicit parent source")
		}
		if state.TokenHash != prior.TokenHash || state.AwebURL != prior.AwebURL || state.Alias != prior.Alias || state.Address != prior.Address || state.Scope != prior.Scope || state.NoAddress != prior.NoAddress || state.DIDKey != prior.DIDKey || state.StableID != prior.StableID {
			return nil, errors.New("hosted invite retry changed the original token, child key, scope or creation selection")
		}
		state = prior
	}
	if _, err := state.selectParent(parentHome); err != nil {
		return nil, err
	}
	if state.InviteID != "" {
		return state, nil
	}
	if state.Tree == nil {
		var err error
		state.Tree, err = newHostedIDTreeRecovery(hostedIdentityContext{})
		if err != nil {
			return nil, err
		}
	}
	// The key exists before preview. Retain its provenance first, including
	// when preview fails and no invitation metadata can be saved yet.
	if recoveryPath != "" {
		if err := state.save(recoveryPath); err != nil {
			return nil, err
		}
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
	tree := state.Tree
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
			state.MembershipOnly = true
			return nil, nil
		}
	}
	if !state.parentageSelected() || state.Tree.Domain == "" {
		state.MembershipOnly = true
		return nil, missingInviteHumanChain(state.ForHuman)
	}
	if material.IdentityScope == awid.IdentityModeGlobal && strings.HasPrefix(fmt.Sprint(state.Tree.Parent["id"]), "did:key:") {
		return nil, unregisteredInviteParentError()
	}
	state.IssuerCreationStarted = true
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
			leaf, err := installed.Leaf()
			if err != nil {
				return nil, err
			}
			subject := material.DIDKey
			if material.IdentityScope == awid.IdentityModeGlobal {
				subject = material.StableID
			}
			if leaf.ID() != subject || leaf.Kind() != awid.IDCertificateKindAgent || leaf.Domain() != state.Tree.Domain || !reflect.DeepEqual(leaf.Parent().Fields(), state.Tree.Parent) {
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

func (state *hostedInviteCreation) parentageSelected() bool {
	return state.MintedKey == nil || *state.MintedKey || state.ParentHome != "" || (state.ParentFromSource != nil && *state.ParentFromSource)
}

func unregisteredInviteParentError() error {
	return fmt.Errorf("%w: a registered child needs a registered parent; be adopted by the person directly with aw id parent request --human, or join from a registered source", &awid.IDCertificateError{Code: "unregistered_parent"})
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
func releaseRefusedHostedInvite(recoveryPath string, refusal error) error {
	definitive := awid.IDCertificateErrorCode(refusal) == "human_mismatch"
	status, hasStatus := awid.HTTPStatusCode(refusal)
	if hasStatus && status == http.StatusConflict && awid.RefusalCode(refusal) == "human_condition_mismatch" {
		definitive = true
	}
	if !definitive {
		return refusal
	}
	if err := discardHostedInviteAttempt(recoveryPath); err != nil {
		return errors.Join(refusal, err)
	}
	return refusal
}

func discardHostedInviteAttempt(recoveryPath string) error {
	// The pending marker is the key's provenance: acceptance minted it and
	// it has never joined. A replacement invite may reuse that same key;
	// only successful acceptance removes this marker.
	if err := os.Remove(recoveryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("release refused invite recovery: %w", err)
	}
	return nil
}

func canResumeHostedInvite(token, home string) bool {
	if !awid.IsHostedSpawnInviteToken(token) {
		return false
	}
	for _, name := range []string{"grant.yaml", "teams.yaml", "workspace.yaml"} {
		if _, err := os.Stat(filepath.Join(home, name)); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	state, err := loadHostedInviteCreation(filepath.Join(home, hostedInviteRecoveryFile))
	if err != nil || state == nil || state.Scope != "local" || state.TokenHash != strings.TrimPrefix(hostedTeamInviteRecordID(token), "hosted-") {
		return false
	}
	key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	return err == nil && awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) == state.DIDKey
}
