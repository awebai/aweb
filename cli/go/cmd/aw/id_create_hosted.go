package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
)

const cliIdentityCreatePath = "/api/v1/cli/identities"

var hostedIdentityTeamUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// The recovery association is persisted before any remote effect. A retry must
// use the same host account, destination, policy and locally held key.
type hostedIdentityContext struct {
	Issuer      string `json:"issuer"`
	AccountID   string `json:"account_id"`
	OwnerDIDKey string `json:"owner_did_key,omitempty"`
	Org         string `json:"org"`
	TeamID      string `json:"team_id"`
	Name        string `json:"name"`
	InboundMode string `json:"inbound_mode"`
	RegistryURL string `json:"registry_url"`
	Domain      string `json:"domain,omitempty"`
	ParentID    string `json:"parent_id,omitempty"`
	ParentKind  string `json:"parent_kind,omitempty"`
}

type hostedIdentityRecovery struct {
	ResponseJSON string                `json:"response_json,omitempty"`
	Version      int                   `json:"version"`
	Context      hostedIdentityContext `json:"context"`
	SigningSeed  string                `json:"signing_seed"`
	IDTree       *hostedIDTreeRecovery `json:"id_tree"`
}

type hostedIdentityResponse struct {
	awid.IDTreeCreationResponse
	TeamID          string `json:"team_id"`
	CanonicalTeamID string `json:"canonical_team_id"`
	IdentityID      string `json:"identity_id"`
	AgentID         string `json:"agent_id"`
	Name            string `json:"name"`
	DID             string `json:"did"`
	StableID        string `json:"stable_id"`
	IdentityScope   string `json:"identity_scope"`
	Custody         string `json:"custody"`
	Namespace       string `json:"namespace"`
	Address         string `json:"address"`
	InboundMode     string `json:"inbound_mode"`
	TeamCert        string `json:"team_cert"`
	Created         bool   `json:"created"`
	APIKey          string `json:"api_key"`
}

func runHostedIdentityCreate(cmd *cobra.Command) error {
	org, _ := cmd.Flags().GetString("org")
	teamID, _ := cmd.Flags().GetString("team-id")
	rawMode, _ := cmd.Flags().GetString("inbound-mode")
	org, teamID, name := strings.TrimSpace(org), strings.TrimSpace(teamID), strings.TrimSpace(idCreateName)
	_, _, canonicalErr := awid.ParseTeamID(teamID)
	if org == "" || name == "" || (!hostedIdentityTeamUUID.MatchString(teamID) && canonicalErr != nil) {
		return usageError("--org, --name and --team-id (a service UUID or canonical name:namespace) are required")
	}
	if cmd.Flags().Changed("domain") || cmd.Flags().Changed("skip-dns-verify") {
		return usageError("--domain and --skip-dns-verify cannot be combined with --org")
	}
	mode := "team_and_contacts"
	if cmd.Flags().Changed("inbound-mode") {
		var err error
		mode, err = normalizeInboundModeCLIValue(rawMode)
		if err != nil {
			return err
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if home.Source != awconfig.IdentityHomeFlag {
		return usageError("hosted identity creation requires an explicit fresh --identity-home credential root")
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	var cfg cliAuthConfig
	var account cliAuthAccount
	var owner *hostedOwnerAuthority
	if cmd.Flags().Changed("owner-identity-home") {
		if strings.TrimSpace(serverFlag) != "" {
			return usageError("the owner root's workspace binding selects the service; omit --server-name")
		}
		rawOwner, _ := cmd.Flags().GetString("owner-identity-home")
		owner, err = loadHostedOwnerAuthority(wd, home, rawOwner)
		if err != nil {
			return err
		}
		cfg.Issuer = owner.issuer
	} else {
		cfg, account, err = requireOrgCLIAuth(ctx)
		if err != nil {
			return orgCommandError(cmd, err)
		}
	}
	// The human OAuth issuer names the site origin; ordinary identity APIs
	// may be mounted below it. Save the resolved API base in the new root.
	rawAPI := cfg.Issuer
	if owner != nil {
		rawAPI = owner.apiURL
	}
	apiBase, err := resolveWorkingBaseURLContext(ctx, rawAPI)
	if err != nil {
		return err
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(idCreateRegistryURL) != "" {
		if err := registry.SetFallbackRegistryURL(strings.TrimSpace(idCreateRegistryURL)); err != nil {
			return err
		}
	}
	var selectedIssuer *selectedChildIssuer
	var human *hostedHumanParent
	if owner != nil {
		if idCreateHumanParent != "" || idCreateRootParent {
			return usageError("the selected native owner is the parent; omit --human-parent and --root-parent")
		}
		selectedIssuer, err = hostedOwnerIssuer(ctx, wd, owner, registry, nil)
	} else {
		human, err = selectHostedPersonParent(account, strings.TrimSpace(idCreateHumanParent), idCreateRootParent)
	}
	if err != nil {
		return err
	}
	if human != nil {
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Human parent: %s (%s)\n", human.ID, human.Domain); err != nil {
			return err
		}
	}
	association := hostedIdentityContext{Issuer: cfg.Issuer, AccountID: account.ID, Org: org, TeamID: teamID, Name: name, InboundMode: mode, RegistryURL: registry.DefaultRegistryURL}
	if owner != nil {
		association.OwnerDIDKey = owner.did
	}
	if selectedIssuer != nil {
		association.Domain = selectedIssuer.domain
		association.ParentKind = "identity"
		association.ParentID = selectedIssuer.parent["id"].(string)
	}
	if human != nil {
		association.Domain = human.Domain
		association.ParentKind = "identity"
		association.ParentID = human.ID
	}
	if association.Domain != "" {
		_, origin, routeErr := childIssuerRegistry(ctx, idChildOptions{RegistryURL: idCreateRegistryURL}, association.Domain)
		if routeErr != nil {
			return routeErr
		}
		association.RegistryURL = origin
	}
	statePath := filepath.Join(home.Root, "hosted-identity-create.json")
	if err := pathpreflight.PreflightDir(home.Root, "hosted identity credential root", pathpreflight.Options{}); err != nil {
		return err
	}
	if err := pathpreflight.PreflightFile(statePath+".lock", "hosted identity recovery lock", pathpreflight.Options{}); err != nil {
		return err
	}
	lock, err := awconfig.TryLockExclusive(statePath + ".lock")
	if err != nil {
		return fmt.Errorf("hosted identity creation already in progress or recovery lock unavailable: %w", err)
	}
	defer lock.Close()
	material, err := prepareHostedIdentity(home.Root, statePath, association)
	if err != nil {
		return err
	}
	mapping, err := registry.RegisterIdentity(ctx, association.RegistryURL, material.DIDKey, material.StableID, material.SigningKey)
	if err != nil {
		var registered *awid.AlreadyRegisteredError
		if !errors.As(err, &registered) || registered.DIDAW != material.StableID || registered.ExistingDIDKey != material.DIDKey {
			return fmt.Errorf("register original hosted identity: %w", err)
		}
	} else if mapping == nil || mapping.DIDAW != material.StableID || mapping.CurrentDIDKey != material.DIDKey {
		return errors.New("registry response does not match the original hosted identity")
	}
	state, err := loadHostedIdentityRecovery(statePath)
	if err != nil {
		return err
	}
	var nativeChain map[string]any
	if selectedIssuer != nil && state.ResponseJSON == "" {
		step := agentChainStep{issuer: selectedIssuer.childIssuer, agentID: material.StableID, agentDIDKey: material.DIDKey, agentKey: material.SigningKey, domain: association.Domain, registryURL: association.RegistryURL, registry: registry, identityDir: home.Root, now: time.Now().UTC()}
		nativeChain, err = step.issue(ctx)
		if err != nil {
			return err
		}
		header, headerErr := awid.EncodeIDChainHeader(nativeChain)
		if headerErr != nil {
			return headerErr
		}
		if state.IDTree.NativeChainHeader != "" && state.IDTree.NativeChainHeader != header {
			return errors.New("native owner retry changed the original child certificate")
		}
		state.IDTree.NativeChainHeader = header
		if err := saveHostedIdentityRecovery(statePath, state); err != nil {
			return err
		}
		if _, err := finishHostedIDTree(ctx, state.IDTree, awid.IDTreeCreationResponse{IDChain: awid.ReceivedIDChain(nativeChain), RegistrationRequest: &awid.IDTreeRegistrationRequest{}}, material, home.Root, registry, nil); err != nil {
			return err
		}
	} else if selectedIssuer != nil {
		nativeChain, err = awid.DecodeIDChainHeader(state.IDTree.NativeChainHeader)
		if err != nil {
			return err
		}
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	audience, err := cliAuthIssuerAudience(cfg.Issuer)
	if err != nil {
		return err
	}
	payload := map[string]any{"operation": "cli_global_identity_create.v1", "aud": audience, "method": http.MethodPost, "path": cliIdentityCreatePath, "org": org, "team_id": teamID, "name": name, "did": material.DIDKey, "inbound_mode": mode, "timestamp": timestamp}
	treeRequest := state.IDTree.request(nativeChain)
	if treeRequest != nil {
		// Both the child intent and outer owner envelope cover the complete object.
		treeJSON, marshalErr := json.Marshal(treeRequest)
		if marshalErr != nil {
			return marshalErr
		}
		var treeValue map[string]any
		decoder := json.NewDecoder(bytes.NewReader(treeJSON))
		decoder.UseNumber()
		if err := decoder.Decode(&treeValue); err != nil {
			return err
		}
		payload["id_tree"] = treeValue
	}
	canonical, err := awid.CanonicalJSONValue(payload)
	if err != nil {
		return err
	}
	request := map[string]any{"org": org, "team_id": teamID, "name": name, "did": material.DIDKey, "inbound_mode": mode, "proof": workspaceTeamEnrollProof{Type: "didkey-intent-v1", Timestamp: timestamp, Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(material.SigningKey, []byte(canonical)))}}
	if treeRequest != nil {
		request["id_tree"] = treeRequest
	}
	var response hostedIdentityResponse
	err = readHostedCreationResponse(state.ResponseJSON, &response, func() error {
		if owner != nil {
			return postHostedOwnerIdentity(ctx, owner, request, &response)
		}
		return postCLIAuthJSON(ctx, cfg.Issuer, cliIdentityCreatePath, cfg.AccessToken, request, &response)
	})
	if err != nil {
		if nativeChain != nil {
			return fmt.Errorf("identity independently registered; hosted membership could not be confirmed: %w", err)
		}
		return orgCommandError(cmd, err)
	}
	cert, err := validateHostedIdentityResponse(response, association, material)
	if err != nil {
		return err
	}
	if err := state.IDTree.retainResponse(response.IDTreeCreationResponse); err != nil {
		return err
	}
	if state.ResponseJSON == "" {
		state.ResponseJSON, err = canonicalHostedCreationResponse(response, response.IDTreeCreationResponse)
		if err != nil {
			return err
		}
	}
	if err := saveHostedIdentityRecovery(statePath, state); err != nil {
		return err
	}
	if nativeChain != nil {
		header, headerErr := awid.EncodeIDChainHeader(map[string]any(response.IDChain))
		if headerErr != nil || header != state.IDTree.NativeChainHeader || response.RegistrationRequest != nil {
			return errors.New("hosted response did not accept the original registered native chain")
		}
	}
	responsibility, err := finishHostedIDTree(ctx, state.IDTree, response.IDTreeCreationResponse, material, home.Root, registry, nil)
	if err != nil {
		return fmt.Errorf("hosted membership created; attribution installation incomplete: %w", err)
	}
	enrollment := &workspaceTeamEnrollResponse{TeamID: response.TeamID, CanonicalTeamID: response.CanonicalTeamID, Alias: name, DID: response.DID, StableID: response.StableID, IdentityScope: response.IdentityScope, IdentityID: response.IdentityID, AgentID: response.AgentID}
	if err := installWorkspaceTeamEnrollment(home.Root, home.Root, apiBase, material, enrollment, cert, association.RegistryURL); err != nil {
		return fmt.Errorf("hosted identity exists; retry with the original root and parameters to finish installation: %w", err)
	}
	if err := requireCreatedIdentityInboundMode(cmd, home.Root, home.Root, apiBase, response.CanonicalTeamID, mode); err != nil {
		return err
	}
	// Recovery material is only for an incomplete operation. In particular it
	// must not retain a second signing seed after this identity rotates its key.
	if err := os.Remove(statePath); err != nil {
		return fmt.Errorf("remove completed hosted identity recovery material: %w", err)
	}
	// Retain the empty lock: unlinking an open lock fails on Windows, and on
	// Unix it can split concurrent callers across different lock-file inodes.
	status := "reused"
	if response.Created {
		status = "created"
	}
	out := map[string]any{"status": status, "team_id": response.CanonicalTeamID, "service_team_id": response.TeamID, "identity_home": home.Root, "identity_scope": "global", "custody": "self", "did_key": material.DIDKey, "did_aw": material.StableID, "address": response.Address, "inbound_mode": mode}
	out["id_registration"] = "unknown"
	out["responsibility"] = awid.IDChainResult{Outcome: "unknown", Reason: "legacy_no_chain"}
	if responsibility != nil {
		out["id_registration"] = "registered"
		out["responsibility"] = responsibility
	}
	if human != nil {
		out["human_parent"] = human.ID
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Status: %s\nAddress: %s\nTeam: %s\nIdentity home: %s\nInbound mode: %s\nID registration: %s\n", status, response.Address, response.CanonicalTeamID, home.Root, mode, out["id_registration"])
	return err
}

func prepareHostedIdentity(root, statePath string, association hostedIdentityContext) (workspaceTeamIdentityMaterial, error) {
	if err := pathpreflight.PreflightFile(statePath, "hosted identity recovery state", pathpreflight.Options{}); err != nil {
		return workspaceTeamIdentityMaterial{}, err
	}
	var key ed25519.PrivateKey
	data, err := os.ReadFile(statePath)
	switch {
	case err == nil:
		info, err := os.Stat(statePath)
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		if info.Mode().Perm()&0077 != 0 {
			return workspaceTeamIdentityMaterial{}, errors.New("hosted identity recovery state must be private (0600)")
		}
		var state hostedIdentityRecovery
		if json.Unmarshal(data, &state) != nil || state.Version != 1 {
			return workspaceTeamIdentityMaterial{}, errors.New("invalid hosted identity recovery state; retain the original root for reconciliation")
		}
		if state.Context != association {
			return workspaceTeamIdentityMaterial{}, usageError("hosted identity root belongs to different creation parameters; retry the original account, organization, team, name, mode and registry")
		}
		seed, err := base64.StdEncoding.DecodeString(state.SigningSeed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return workspaceTeamIdentityMaterial{}, errors.New("invalid signing material in hosted identity recovery state")
		}
		key = ed25519.NewKeyFromSeed(seed)
		if state.IDTree == nil {
			state.IDTree, err = newHostedIDTreeRecovery(association)
			if err != nil {
				return workspaceTeamIdentityMaterial{}, err
			}
			if err := saveHostedIdentityRecovery(statePath, &state); err != nil {
				return workspaceTeamIdentityMaterial{}, err
			}
		}
	case os.IsNotExist(err):
		entries, err := os.ReadDir(root)
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		for _, entry := range entries {
			if entry.Name() != filepath.Base(statePath)+".lock" {
				return workspaceTeamIdentityMaterial{}, usageError("hosted identity creation requires a fresh root or its original recovery state; selected root is occupied")
			}
		}
		_, key, err = awid.GenerateKeypair()
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		tree, err := newHostedIDTreeRecovery(association)
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		data, err = json.Marshal(hostedIdentityRecovery{Version: 1, Context: association, SigningSeed: base64.StdEncoding.EncodeToString(key.Seed()), IDTree: tree})
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		if err := awid.AtomicWriteFile(statePath, data); err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
	default:
		return workspaceTeamIdentityMaterial{}, err
	}
	pub := key.Public().(ed25519.PublicKey)
	material := workspaceTeamIdentityMaterial{SigningKey: key, PublicKey: pub, DIDKey: awid.ComputeDIDKey(pub), StableID: awid.ComputeStableID(pub), IdentityScope: awid.IdentityModeGlobal, Alias: association.Name}
	// An interrupted installation may already contain this key, but never replace
	// an unrelated installed key or identity while recovering an operation.
	installed, err := awid.LoadSigningKey(filepath.Join(root, "signing.key"))
	if err == nil && !installed.Equal(key) {
		return workspaceTeamIdentityMaterial{}, errors.New("installed signing key differs from original hosted creation")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return workspaceTeamIdentityMaterial{}, err
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(root, "identity.yaml"))
	if err == nil && (identity.DID != material.DIDKey || identity.StableID != material.StableID) {
		return workspaceTeamIdentityMaterial{}, errors.New("installed identity differs from original hosted creation")
	}
	if err != nil && !os.IsNotExist(err) {
		return workspaceTeamIdentityMaterial{}, err
	}
	return material, nil
}

func validateHostedIdentityResponse(response hostedIdentityResponse, context hostedIdentityContext, material workspaceTeamIdentityMaterial) (*awid.TeamCertificate, error) {
	domain, _, err := awid.ParseTeamID(response.CanonicalTeamID)
	// Cloud alone resolves the selector under the authorized organization. Keep
	// its exact supplied spelling in the intent and recovery; bind the response
	// to the selected form without doing another lookup here.
	teamMatches := false
	if hostedIdentityTeamUUID.MatchString(context.TeamID) {
		teamMatches = strings.EqualFold(response.TeamID, context.TeamID)
	} else if selectedDomain, selectedName, parseErr := awid.ParseTeamID(context.TeamID); parseErr == nil {
		teamMatches = response.CanonicalTeamID == awid.BuildTeamID(selectedDomain, selectedName)
	}
	if err != nil || !hostedIdentityTeamUUID.MatchString(response.TeamID) || !teamMatches || response.Namespace != domain || response.Name != context.Name || response.Address != domain+"/"+context.Name || response.DID != material.DIDKey || response.StableID != material.StableID || response.IdentityScope != awid.IdentityModeGlobal || response.Custody != awid.CustodySelf || response.InboundMode != context.InboundMode || response.IdentityID == "" || response.AgentID == "" || response.APIKey != "" {
		return nil, errors.New("hosted identity response does not match the requested identity, team and inbound mode")
	}
	cert, err := decodeWorkspaceTeamTeamCert(response.TeamCert)
	if err != nil {
		return nil, err
	}
	if err := verifyAPIKeyBootstrapCertificate(cert); err != nil {
		return nil, err
	}
	if cert.Team != response.CanonicalTeamID || cert.Alias != context.Name || cert.MemberDIDKey != material.DIDKey || cert.MemberDIDAW != material.StableID || cert.MemberAddress != response.Address || cert.IdentityScope != awid.IdentityModeGlobal {
		return nil, errors.New("hosted identity certificate does not match the requested identity and team")
	}
	return cert, nil
}

// The existing identity client and endpoint enforce certificate authentication.
// Reading a mode is not replacing it: an old service's downgrade is a failure.
func requireCreatedIdentityInboundMode(cmd *cobra.Command, workingDir, identityRoot, serverURL, teamID, expected string) error {
	home := awconfig.IdentityHome{Root: identityRoot, Source: awconfig.IdentityHomeFlag}
	if identityRoot == "" || filepath.Clean(identityRoot) == awconfig.WorktreeIdentityHome(workingDir) {
		home = awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(workingDir), Source: awconfig.IdentityHomeDefault}
	}
	selection, err := resolveSelectionAtIdentityHome(workingDir, teamID, home)
	if err != nil {
		return err
	}
	certificateClient, err := resolveCertificateClient(selection, serverURL)
	if err != nil {
		return err
	}
	if certificateClient == nil {
		return errors.New("inbound mode verification requires the installed team certificate")
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	actual, err := certificateClient.GetMyInboundMode(ctx)
	if err != nil {
		return fmt.Errorf("identity created but effective inbound mode could not be verified; retain the original root: %w", err)
	}
	if actual == nil || actual.InboundMode != expected || actual.IdentityScope != awid.IdentityModeGlobal || actual.AgentID == "" {
		return usageError("inbound_mode_mismatch: created identity's effective mode does not match %s; retain the original root for reconciliation", expected)
	}
	return nil
}

func (response *hostedIdentityResponse) UnmarshalJSON(raw []byte) error {
	type plain hostedIdentityResponse
	if err := json.Unmarshal(raw, (*plain)(response)); err != nil {
		return err
	}
	tree, err := awid.DecodeIDTreeCreationResponse(raw)
	if err != nil {
		return err
	}
	response.IDTreeCreationResponse = tree
	return nil
}
