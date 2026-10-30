package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const hostedInviteRecoveryFile = "hosted-invite-creation.json"

type hostedInviteCreation struct {
	TokenHash    string                `json:"token_hash"`
	AwebURL      string                `json:"aweb_url"`
	Alias        string                `json:"alias"`
	Address      string                `json:"address"`
	Scope        string                `json:"scope"`
	NoAddress    bool                  `json:"no_address"`
	DIDKey       string                `json:"did_key"`
	StableID     string                `json:"stable_id"`
	InviteID     string                `json:"invite_id"`
	TeamID       string                `json:"team_id"`
	Tree         *hostedIDTreeRecovery `json:"id_tree"`
	RequestReady bool                  `json:"request_ready"`
	ResponseJSON string                `json:"response_json,omitempty"`
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
	if err := json.Unmarshal(raw, &state); err != nil {
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
	state := &hostedInviteCreation{TokenHash: hex.EncodeToString(digest[:]), AwebURL: origin, Alias: alias, Address: address, NoAddress: noAddress, Scope: material.IdentityScope, DIDKey: material.DIDKey, StableID: material.StableID}
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
		return nil, previewErr
	}
	if !wire.IDTreePresent || !hostedIdentityTeamUUID.MatchString(wire.InviteID) {
		return nil, errors.New("hosted invite preview omitted its invitation ID or explicit ID-tree metadata")
	}
	state.InviteID, state.TeamID = wire.InviteID, wire.CanonicalTeamID
	tree, err := newHostedIDTreeRecovery(hostedIdentityContext{})
	state.Tree = tree
	if err != nil {
		return nil, err
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
	if material.IdentityScope == awid.IdentityModeGlobal && strings.HasPrefix(pinned.IssuerID, "did:key:") {
		return nil, &awid.IDCertificateError{Code: "unregistered_parent"}
	}
	state.Tree.Domain = pinned.Domain
	state.Tree.Parent = map[string]any{"kind": "identity", "id": pinned.IssuerID}
	state.Tree.Mode = pinned.Mode
	return state, nil
}

func (state *hostedInviteCreation) prepareRequest(root string, material workspaceTeamIdentityMaterial) (*awid.IDTreeCreationRequest, error) {
	if state.Tree.Domain == "" {
		return nil, nil
	}
	if !state.RequestReady {
		installed, err := awconfig.LoadInstalledIDChain(root)
		if err != nil {
			return nil, err
		}
		if installed == nil && state.Tree.Mode == "self_custodial" {
			return nil, fmt.Errorf("native agent signature pending: obtain and import an agent child of %s in %s with the existing ID parent exchange, then retry this invite in the same identity home", state.Tree.Parent["id"], state.Tree.Domain)
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
	if state == nil || state.Scope != "local" || state.StableID != "" || state.Tree.Mode != "self_custodial" || state.Tree.Domain == "" || state.Tree.Parent["kind"] != "identity" {
		return nil, os.ErrNotExist
	}
	if opts.Domain != "" && opts.Domain != state.Tree.Domain {
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
	return &requester{id: state.DIDKey, didKey: state.DIDKey, domain: state.Tree.Domain, kind: "agent", dir: home.Root, expectedParent: state.Tree.Parent, signer: func(string) awid.IDCertificateSigner { return awid.KeySigner(key) }}, nil
}
