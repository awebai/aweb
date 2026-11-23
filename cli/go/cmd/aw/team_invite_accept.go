package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type teamInviteAcceptanceRequest struct {
	Token      string
	WorkingDir string
	Options    teamAcceptInviteOptions
}

type teamInviteConnectionTarget struct {
	Token        string
	PreferredURL string
	Accepted     *acceptedTeamInvite
}

// Native connection follows the issuer's saved route after acceptance; an
// unsigned token hint never overrides it (docs/cli-integration-contract.md:143-145).
// Hosted tokens retain their service-envelope selection.
func acceptedInviteServiceURL(target teamInviteConnectionTarget) string {
	acceptedURL := firstNonEmptyString(strings.TrimSpace(target.Accepted.AwebURL), strings.TrimSpace(target.Accepted.Output.AwebURL))
	if awid.IsHostedSpawnInviteToken(target.Token) {
		return firstNonEmptyString(strings.TrimSpace(target.PreferredURL), acceptedURL)
	}
	return acceptedURL
}

type teamInviteCompletionMode uint8

const (
	teamInviteInstallMembership teamInviteCompletionMode = iota + 1
	teamInviteConnectWorkspace
)

// Local membership cannot acquire global address authority (docs/identity.md:247-253).
func validateTeamInviteAcceptance(request teamInviteAcceptanceRequest) (string, error) {
	workingDir, opts := request.WorkingDir, request.Options
	scope := strings.TrimSpace(opts.Scope)
	if scope == "" {
		scope = awid.IdentityModeLocal
	}
	if scope != awid.IdentityModeLocal && scope != awid.IdentityModeGlobal {
		return "", usageError("identity scope must be --local or --global")
	}
	if scope == awid.IdentityModeLocal {
		if strings.TrimSpace(opts.Address) != "" {
			return "", usageError("--address requires --global")
		}
		if opts.NoAddress {
			return "", usageError("--no-address requires --global")
		}
	}
	if opts.NoAddress && strings.TrimSpace(opts.Address) != "" {
		return "", usageError("--address and --no-address cannot be used together")
	}
	if err := ensureTeamAcceptScopeAllowed(workingDir, opts.IdentityHome, scope); err != nil {
		return "", err
	}

	return scope, nil
}

type nativeInviteDefaultClaimRequest struct {
	Plan        teamMemberEnrollmentPlan
	Registry    *awid.RegistryClient
	RegistryURL string
}

func claimNativeInviteDefaultAddress(ctx context.Context, request nativeInviteDefaultClaimRequest) (*awid.AtomicAddressClaimResult, error) {
	plan, registry, registryURL := request.Plan, request.Registry, request.RegistryURL
	if plan.DefaultClaim == nil {
		return nil, nil
	}
	dryRun := *plan.DefaultClaim
	dryRun.DryRun = true
	if _, err := registry.ClaimIdentityAddressAt(ctx, registryURL, dryRun); err != nil {
		return nil, idAddressClaimAtomicError(plan.MemberAddress, registryURL, err)
	}
	commit := *plan.DefaultClaim
	commit.DryRun = false
	applied, err := registry.ClaimIdentityAddressAt(ctx, registryURL, commit)
	if err != nil {
		return nil, idAddressClaimAtomicError(plan.MemberAddress, registryURL, err)
	}
	return applied, nil
}

type hostedInviteAddressClaimRequest struct {
	MemberAddress string
	Material      workspaceTeamIdentityMaterial
}

// An existing global identity signs its address claim (docs/identity.md:247-253).
func buildHostedInviteAddressClaim(ctx context.Context, request hostedInviteAddressClaimRequest) (string, *awid.AtomicAddressClaimIdentityProof, error) {
	memberAddress := request.MemberAddress
	pub, signingKey := request.Material.PublicKey, request.Material.SigningKey
	stableID, didKey := request.Material.StableID, request.Material.DIDKey
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return "", nil, err
	}
	registryURL := strings.TrimSpace(registry.DefaultRegistryURL)
	domain, name, err := parseAddress(memberAddress)
	if err != nil {
		return "", nil, err
	}
	var logProof *awid.DidKeyEvidence
	if awid.ComputeStableID(pub) != stableID {
		resolution, err := registry.ResolveKeyAt(ctx, registryURL, stableID)
		if err != nil {
			return "", nil, fmt.Errorf("resolve did log head for hosted global identity %s: %w", stableID, err)
		}
		if strings.TrimSpace(resolution.CurrentDIDKey) != didKey {
			return "", nil, fmt.Errorf("registry current did:key for %s is %s, not %s", stableID, resolution.CurrentDIDKey, didKey)
		}
		logProof = resolution.LogHead
		if logProof == nil {
			return "", nil, fmt.Errorf("registry did log for hosted global identity %s has no log head", stableID)
		}
	}
	atomicAddressClaim, err := awid.BuildAtomicAddressClaimIdentityProof(awid.AtomicAddressClaimFields{
		Operation:        awid.AtomicAddressClaimOperation,
		Domain:           domain,
		AddressName:      name,
		DIDAW:            stableID,
		CurrentDIDKey:    didKey,
		RegistryURL:      registryURL,
		DryRun:           false,
		IdentityCustody:  string(awid.AddressClaimCustodySelf),
		NamespaceCustody: string(awid.AddressClaimCustodyHostedCustodial),
		DIDLogProof:      logProof,
	}, signingKey)
	if err != nil {
		return "", nil, fmt.Errorf("build hosted invite atomic address claim proof: %w", err)
	}
	return registryURL, atomicAddressClaim, nil
}

type hostedInviteResponseRequest struct {
	Creation     *hostedInviteCreation
	RecoveryPath string
	Client       *awid.Client
	Request      *awid.SpawnAcceptInviteRequest
}

// Persist submission before network I/O and replay retained answers (docs/identity.md:239-245).
func obtainHostedInviteResponse(ctx context.Context, request hostedInviteResponseRequest) (*awid.SpawnAcceptInviteResponse, error) {
	creation, recoveryPath := request.Creation, request.RecoveryPath
	client, req := request.Client, request.Request
	if creation.ResponseJSON != "" {
		response := &awid.SpawnAcceptInviteResponse{}
		if err := json.Unmarshal([]byte(creation.ResponseJSON), response); err != nil {
			return nil, fmt.Errorf("decode retained hosted invite response: %w; preserve this identity home and restore its recovery record from a trusted backup before retrying the same invite", err)
		}
		return response, nil
	}
	attempted := true
	creation.AcceptAttempted = &attempted
	if err := creation.save(recoveryPath); err != nil {
		return nil, err
	}
	response, err := client.AcceptSpawnInvite(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("accept hosted team invite: %w", err)
	}
	return response, nil
}

type hostedInviteAcceptanceRequest struct {
	WorkingDir    string
	Token         string
	Options       teamAcceptInviteOptions
	Scope         teamInviteMemberScope
	Alias         string
	MemberAddress string
	Material      workspaceTeamIdentityMaterial
	Home          awconfig.IdentityHome
	Creation      *hostedInviteCreation
	RecoveryPath  string
	Client        *awid.Client
}

type hostedInviteSubmissionHistory uint8

const (
	hostedSubmissionUnknown hostedInviteSubmissionHistory = iota
	hostedSubmissionNotAttempted
	hostedSubmissionAttempted
)

func hostedInviteSubmissionBefore(creation *hostedInviteCreation) hostedInviteSubmissionHistory {
	if creation.AcceptAttempted == nil {
		return hostedSubmissionUnknown
	}
	if *creation.AcceptAttempted {
		return hostedSubmissionAttempted
	}
	return hostedSubmissionNotAttempted
}

// Release only a definite refusal without an earlier unresolved submission.
// Retained 4xx errors explain how to reconcile the same identity and invite.
func finishHostedInviteRefusal(request hostedInviteAcceptanceRequest, history hostedInviteSubmissionHistory, cause error) error {
	localMismatch := awid.IDCertificateErrorCode(cause) == "human_mismatch"
	if request.Creation.ResponseJSON == "" && history != hostedSubmissionAttempted &&
		(history == hostedSubmissionNotAttempted || localMismatch) {
		cause = releaseRefusedHostedInvite(request.RecoveryPath, cause)
	}
	if status, ok := awid.HTTPStatusCode(cause); ok && status >= 400 && status < 500 {
		if _, err := os.Stat(request.RecoveryPath); err == nil {
			return uncertainHostedInviteError(request.Home.Root, request.Creation.TeamID, cause)
		}
	}
	return cause
}

type hostedInviteChildPreparation struct {
	LocalLink      *awconfig.TeamInvite
	ParentInviteID string
	TreeRequest    *awid.IDTreeCreationRequest
}

func prepareHostedInviteChild(ctx context.Context, request hostedInviteAcceptanceRequest) (hostedInviteChildPreparation, error) {

	workingDir := request.WorkingDir
	token := request.Token
	opts := request.Options
	scope := string(request.Scope)
	material := request.Material
	home := request.Home
	creation := request.Creation
	recoveryPath := request.RecoveryPath

	var err error
	parentInviteID := ""
	if opts.ParentHome != "" {
		if err := completeExplicitInviteParent(ctx, workingDir, home.Root, token, opts.ParentHome); err != nil {
			return hostedInviteChildPreparation{}, err
		}
		parentInviteID, _, err = loadTeamInviteParentRecord(token, home.Root)
		if err != nil {
			return hostedInviteChildPreparation{}, err
		}
	}
	var localLink *awconfig.TeamInvite
	if scope == awid.IdentityModeLocal && creation.Tree.Mode == "self_custodial" {
		localLink, err = localHostedInviteLink(token, creation)
		if err != nil {
			return hostedInviteChildPreparation{}, &hostedInviteSignaturePendingError{err: fmt.Errorf("native agent signature pending in %s; child key and request retained: %w", home.Root, err)}
		}
	}
	var treeRequest *awid.IDTreeCreationRequest
	if creation.ResponseJSON == "" {
		treeRequest, err = creation.prepareRequest(home.Root, material)
		if saveErr := creation.save(recoveryPath); saveErr != nil {
			return hostedInviteChildPreparation{}, saveErr
		}
		var pending *hostedInviteSignaturePendingError
		if errors.As(err, &pending) && localLink != nil {
			if exchangeErr := completeLocalHostedInvite(ctx, localLink, creation, workingDir, home.Root); exchangeErr != nil {
				return hostedInviteChildPreparation{}, &hostedInviteSignaturePendingError{err: fmt.Errorf("native agent signature pending in %s; child key and request retained: %w", home.Root, exchangeErr)}
			}
			treeRequest, err = creation.prepareRequest(home.Root, material)
		}
		if err != nil {
			return hostedInviteChildPreparation{}, err
		}
		if err := creation.save(recoveryPath); err != nil {
			return hostedInviteChildPreparation{}, err
		}
	}

	return hostedInviteChildPreparation{LocalLink: localLink, ParentInviteID: parentInviteID, TreeRequest: treeRequest}, nil
}

type hostedInviteAcceptedResponseRequest struct {
	Acceptance       hostedInviteAcceptanceRequest
	Response         *awid.SpawnAcceptInviteResponse
	Registry         *awid.RegistryClient
	RegistryURL      string
	MembershipResult *awid.IDChainResult
	LocalLink        *awconfig.TeamInvite
	ParentInviteID   string
}

func completeHostedInviteResponse(ctx context.Context, responseRequest hostedInviteAcceptedResponseRequest) (*acceptedTeamInvite, error) {
	request := responseRequest.Acceptance

	workingDir := request.WorkingDir
	opts := request.Options
	scope := string(request.Scope)
	alias := request.Alias
	memberAddress := request.MemberAddress
	home := request.Home
	creation := request.Creation
	recoveryPath := request.RecoveryPath
	signingKey := request.Material.SigningKey
	didKey := request.Material.DIDKey
	stableID := request.Material.StableID

	resp := responseRequest.Response
	registryURL := responseRequest.RegistryURL
	localLink := responseRequest.LocalLink
	cert, serverURL, err := validateHostedTeamInviteAcceptResponse(hostedInviteResponseExpectation{
		Response:  resp,
		DIDKey:    didKey,
		Alias:     alias,
		StableID:  stableID,
		Address:   memberAddress,
		Scope:     scope,
		NoAddress: opts.NoAddress,
	})
	if err != nil {
		return nil, err
	}
	if cert.Team != creation.TeamID {
		return nil, errors.New("hosted membership differs from the preview-selected team")
	}
	if err := creation.Tree.retainResponse(resp.IDTreeCreationResponse); err != nil {
		return nil, err
	}
	if creation.Tree.NativeChainHeader != "" {
		header, headerErr := awid.EncodeIDChainHeader(map[string]any(resp.IDChain))
		if headerErr != nil || header != creation.Tree.NativeChainHeader || resp.RegistrationRequest != nil {
			return nil, errors.New("hosted invite changed the original native child chain")
		}
	}
	if creation.ResponseJSON == "" {
		raw, marshalErr := json.Marshal(resp)
		if marshalErr != nil {
			return nil, marshalErr
		}
		creation.ResponseJSON = string(raw)
	}
	if err := creation.save(recoveryPath); err != nil {
		return nil, err
	}
	selectedTeamRegistry, err := resolveRegistryURLSetting(registryURLSettingInput{ExplicitURL: opts.RegistryURL})
	if err != nil {
		return nil, err
	}
	if selectedTeamRegistry != "" {
		selectedTeamRegistry, err = cleanBaseURL(selectedTeamRegistry)
		if err != nil {
			return nil, fmt.Errorf("invalid team registry URL: %w", err)
		}
	}
	if responseRequest.Registry == nil {
		responseRequest.Registry, err = newConfiguredRegistryClient(nil)
		if err != nil {
			return nil, err
		}
	}
	keyObservation, err := responseRequest.Registry.CheckTeamCertificateCurrentKey(ctx, awid.CurrentTeamCertificateCheck{
		RegistryURL: selectedTeamRegistry,
		Certificate: cert,
	})
	if err != nil {
		return nil, fmt.Errorf("hosted membership is not current: %w; ask the team controller for a current certificate", err)
	}
	responsibility, err := verifyHostedInviteAcceptedAttribution(ctx, responseRequest)
	if err != nil {
		return nil, err
	}
	registration := "unknown"
	if responsibility != nil {
		registration = "registered"
		if scope == awid.IdentityModeLocal {
			registration = "not_required"
		}
	} else {
		responsibility = &awid.IDChainResult{Outcome: "unknown", Reason: "legacy_no_chain"}
	}
	if scope == awid.IdentityModeGlobal {
		if err := persistLocalSigningKeyAndCertificateAt(workingDir, home.Root, signingKey, cert); err != nil {
			return nil, err
		}
	} else if err := persistHostedIdentityState(hostedStatePersistence{
		WorkingDir: workingDir, IdentityHome: home, RegistryURL: registryURL,
		SigningKey: signingKey, Certificate: cert, DIDKey: didKey,
		DIDAW: stableID, MemberAddress: memberAddress, Scope: localHostedIdentity,
	}); err != nil {
		return nil, err
	}
	// Accept completed: clear the pending marker so the home is no longer in
	// pending-accept state. (The completed-identity guard already protects it.)
	if err := (acceptanceMintedKey{Home: home}).remove(); err != nil {
		return nil, err
	}

	if err := os.Remove(recoveryPath); err != nil {
		return nil, err
	}
	if localLink != nil {
		if err := recordConsumedTeamInvite(localLink.InviteID); err != nil {
			return nil, err
		}
	}
	if err := consumeInviteParent(responseRequest.ParentInviteID); err != nil {
		return nil, err
	}
	return &acceptedTeamInvite{
		Output: &teamAcceptInviteOutput{
			IDRegistration: registration,
			TeamKey:        &keyObservation.Evidence,
			Responsibility: responsibility,
			Status:         "accepted",
			TeamID:         cert.Team,
			Alias:          strings.TrimSpace(cert.Alias),
			CertPath:       awconfig.TeamCertificateRelativePath(cert.Team),
		},
		Certificate:         cert,
		RegistryURL:         selectedTeamRegistry,
		observedRegistryURL: keyObservation.RegistryURL,
		AwebURL:             serverURL,
		Domain:              strings.TrimSpace(resp.Namespace),
		TeamName:            strings.TrimSpace(resp.TeamSlug),
	}, nil
}

func completeHostedInviteAcceptance(ctx context.Context, request hostedInviteAcceptanceRequest) (*acceptedTeamInvite, error) {

	token := request.Token
	opts := request.Options
	scope := string(request.Scope)
	alias := request.Alias
	memberAddress := request.MemberAddress
	material := request.Material
	home := request.Home
	creation := request.Creation
	recoveryPath := request.RecoveryPath
	client := request.Client
	pub := request.Material.PublicKey
	didKey := request.Material.DIDKey
	stableID := request.Material.StableID
	child, err := prepareHostedInviteChild(ctx, request)
	if err != nil {
		return nil, err
	}
	localLink, treeRequest := child.LocalLink, child.TreeRequest
	var membershipResult *awid.IDChainResult
	if creation.MembershipOnly || creation.MembershipChain != nil {
		subjectID := didKey
		if scope == awid.IdentityModeGlobal {
			subjectID = stableID
		}
		membershipResult, err = verifyInviteMembership(ctx, creation.MembershipChain, awid.IDChainSubject{ID: subjectID, DIDKey: didKey}, creation.ForHuman, opts.Registry, opts.TXTResolver)
		if err != nil {
			return nil, err
		}
	}
	registry := opts.Registry
	if treeRequest != nil && treeRequest.IDChain != nil {
		if registry == nil {
			registry, err = newConfiguredRegistryClient(nil)
			if err != nil {
				return nil, err
			}
		}
		verdict, err := finishHostedIDTree(ctx, creation.Tree, awid.IDTreeCreationResponse{FieldsPresent: true, IDChain: awid.ReceivedIDChain(treeRequest.IDChain)}, material, home.Root, registry, opts.TXTResolver)
		if err != nil {
			return nil, fmt.Errorf("native invite child chain is not currently valid: %w", err)
		}
		if err := checkInviteHuman(verdict, creation.ForHuman); err != nil {
			return nil, err
		}
	}
	registryURL := ""
	var atomicAddressClaim *awid.AtomicAddressClaimIdentityProof
	if creation.ResponseJSON == "" && scope == awid.IdentityModeGlobal && memberAddress != "" {
		registryURL, atomicAddressClaim, err = buildHostedInviteAddressClaim(ctx, hostedInviteAddressClaimRequest{MemberAddress: memberAddress, Material: material})
		if err != nil {
			return nil, err
		}
	}

	req := &awid.SpawnAcceptInviteRequest{
		IDTree:        treeRequest,
		Token:         strings.TrimSpace(token),
		DID:           didKey,
		PublicKey:     base64.StdEncoding.EncodeToString(pub),
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
	}
	if len(creation.MembershipChain) != 0 {
		req.IDChain = &creation.MembershipChain
	}
	if scope == awid.IdentityModeGlobal {
		req.Name = alias
		req.StableID = stableID
		req.IdentityScope = awid.IdentityModeGlobal
		req.AtomicAddressClaim = atomicAddressClaim
	} else {
		req.Alias = alias
	}
	resp, err := obtainHostedInviteResponse(ctx, hostedInviteResponseRequest{Creation: creation, RecoveryPath: recoveryPath, Client: client, Request: req})
	if err != nil {
		return nil, err
	}

	return completeHostedInviteResponse(ctx, hostedInviteAcceptedResponseRequest{Acceptance: request, Response: resp, Registry: registry, RegistryURL: registryURL, MembershipResult: membershipResult, LocalLink: localLink, ParentInviteID: child.ParentInviteID})

}

type nativeInviteAttributionRequest struct {
	WorkingDir  string
	Token       string
	Options     teamAcceptInviteOptions
	Home        awconfig.IdentityHome
	Invite      *awconfig.TeamInvite
	Plan        teamMemberEnrollmentPlan
	Registry    *awid.RegistryClient
	Attribution nativeInviteAttributionKind
}

type nativeInviteAttributionKind uint8

const (
	nativeInviteExistingIdentity nativeInviteAttributionKind = iota
	nativeInviteChildIdentity
)

// Enrollment verifies the selected recipient chain before issuance (docs/identity.md:227-240).
func prepareNativeInviteAttribution(ctx context.Context, request nativeInviteAttributionRequest) error {
	workingDir, token, opts := request.WorkingDir, request.Token, request.Options
	home, invite, plan := request.Home, request.Invite, request.Plan
	registry := request.Registry
	if request.Attribution == nativeInviteChildIdentity {
		if invite.IDChild.ChildDIDKey != "" && invite.IDChild.ChildDIDKey != plan.MemberDIDKey {
			return fmt.Errorf("invite recipient key changed; restore the original identity")
		}
		invite.IDChild.ChildDIDKey = plan.MemberDIDKey
		if err := awconfig.SaveTeamInvite(invite); err != nil {
			return err
		}
	}
	if opts.ParentHome != "" {
		if err := completeExplicitInviteParent(ctx, workingDir, home.Root, token, opts.ParentHome); err != nil {
			return err
		}
	} else if request.Attribution == nativeInviteChildIdentity {
		if err := prepareInviteChildIdentity(home.Root); err != nil {
			return err
		}
		if err := completeTeamInviteIDChild(ctx, invite, workingDir, home.Root); err != nil {
			return err
		}
	}
	installed, err := awconfig.LoadInstalledIDChain(home.Root)
	if err != nil {
		return err
	}
	var bundle map[string]any
	if installed != nil {
		bundle = installed.Bundle
	} else if invite.ForHuman != nil {
		if err := prepareInviteChildIdentity(home.Root); err != nil {
			return err
		}
	}
	subjectID := plan.MemberDIDKey
	if plan.MemberDIDAW != "" {
		subjectID = plan.MemberDIDAW
	}
	if _, err := verifyInviteMembership(ctx, bundle, awid.IDChainSubject{ID: subjectID, DIDKey: plan.MemberDIDKey}, invite.ForHuman, registry, opts.TXTResolver); err != nil {
		return err
	}
	return nil
}

// Retained success never authorizes a different chain (docs/identity.md:227-245).
func verifyHostedInviteAcceptedAttribution(ctx context.Context, responseRequest hostedInviteAcceptedResponseRequest) (*awid.IDChainResult, error) {
	request := responseRequest.Acceptance
	creation, opts, home := request.Creation, request.Options, request.Home
	material := request.Material
	registry, resp := responseRequest.Registry, responseRequest.Response
	membershipResult := responseRequest.MembershipResult
	var err error
	if registry == nil && resp.IDChain != nil {
		registry, err = newConfiguredRegistryClient(nil)
		if err != nil {
			return nil, err
		}
	}
	responsibility := membershipResult
	if creation.MembershipOnly || creation.MembershipChain != nil {
		if resp.RegistrationRequest != nil {
			return nil, errors.New("membership-only acceptance requested identity registration")
		}
		if resp.IDChain != nil {
			if creation.MembershipChain == nil {
				return nil, errors.New("membership-only acceptance returned a new identity chain; retain the original home and invite for reconciliation")
			}
			expected, err := awid.EncodeIDChainHeader(creation.MembershipChain)
			if err != nil {
				return nil, fmt.Errorf("encode selected membership chain: %w; restore the selected identity's original chain and retry the same invite", err)
			}
			actual, err := awid.EncodeIDChainHeader(map[string]any(resp.IDChain))
			if err != nil {
				return nil, fmt.Errorf("encode accepted membership chain: %w; retain the original home and invite and ask the service operator to repair its chain response before retrying", err)
			}
			if expected != actual {
				return nil, errors.New("membership-only acceptance changed the original chain; retain the original home and invite and ask the service operator to return the selected chain before retrying")
			}
		}
	} else {
		responsibility, err = finishHostedIDTree(ctx, creation.Tree, resp.IDTreeCreationResponse, material, home.Root, registry, opts.TXTResolver)
		if err != nil {
			return nil, fmt.Errorf("hosted membership accepted; identity attribution incomplete, retry the same invite: %w", err)
		}
		if err := checkInviteHuman(responsibility, creation.ForHuman); err != nil {
			return nil, err
		}
	}

	return responsibility, nil
}

type hostedInviteRecipient struct {
	Alias   string
	Address string
}

func resolveHostedInviteRecipient(request teamInviteAcceptanceRequest) (hostedInviteRecipient, error) {
	workingDir, opts := request.WorkingDir, request.Options
	alias := strings.TrimSpace(opts.Name)
	memberAddress := strings.TrimSpace(opts.Address)
	addressName := ""
	if memberAddress != "" {
		_, name, err := parseAddress(memberAddress)
		if err != nil {
			return hostedInviteRecipient{}, err
		}
		addressName = name
	}
	if alias == "" {
		recordedAlias, readErr := resolveAliasFromIdentityAt(teamMembershipLocation{WorkingDir: workingDir, IdentityHome: opts.IdentityHome})
		if readErr != nil {
			return hostedInviteRecipient{}, readErr
		}
		alias = recordedAlias
	}
	if alias == "" && addressName != "" {
		alias = addressName
	}
	if alias == "" {
		return hostedInviteRecipient{}, usageError("--name is required for hosted team invites")
	}
	alias, err := normalizeIDCreateName(alias)
	if err != nil {
		return hostedInviteRecipient{}, err
	}

	return hostedInviteRecipient{Alias: alias, Address: memberAddress}, nil
}

type nativeInviteIssuanceRequest struct {
	Invite             *awconfig.TeamInvite
	Plan               teamMemberEnrollmentPlan
	Home               awconfig.IdentityHome
	ParentInviteID     string
	TeamKey            ed25519.PrivateKey
	Registry           *awid.RegistryClient
	RegistryURL        string
	DefaultClaimResult *awid.AtomicAddressClaimResult
}

// Registry success consumes enrollment before recipient writes (docs/cli-integration-contract.md:146-161).
func issueNativeInviteCertificate(ctx context.Context, request nativeInviteIssuanceRequest) (*awid.TeamCertificate, error) {
	invite, plan, teamKey := request.Invite, request.Plan, request.TeamKey
	registry, registryURL := request.Registry, request.RegistryURL
	appliedDefaultClaim := request.DefaultClaimResult
	teamID := awid.BuildTeamID(invite.Domain, invite.TeamName)
	issuer := teamMembershipIssuer{TeamID: teamID, Key: teamKey, Registry: registry, RegistryURL: registryURL}
	cert, err := issuer.sign(awid.TeamCertificateFields{
		MemberDIDKey:  plan.MemberDIDKey,
		MemberDIDAW:   plan.MemberDIDAW,
		MemberAddress: plan.MemberAddress,
		Alias:         plan.Name,
		IdentityScope: plan.Scope,
	})
	if err != nil {
		return nil, err
	}

	if err := awconfig.BeginTeamInviteIssuance(awconfig.BeginTeamInviteIssuanceInput{
		InviteID:    invite.InviteID,
		Context:     awconfig.TeamInviteIssuanceContext{IdentityHome: request.Home.Root, RegistryURL: registryURL, AwebURL: invite.AwebURL, ParentInviteID: request.ParentInviteID},
		Certificate: *cert,
	}); err != nil {
		return nil, nativeInviteIssuanceRefusal(invite, fmt.Errorf("retain exact issuance before registration: %w", err))
	}
	retained, err := awconfig.LoadTeamInvite(invite.InviteID)
	if err != nil {
		return nil, nativeInviteIssuanceRefusal(invite, fmt.Errorf("read retained issuance before registration: %w", err))
	}
	invite = retained
	if err := registerExactNativeInviteCertificate(ctx, nativeInviteRegistrationRequest{Invite: invite, Certificate: cert, TeamKey: teamKey, MemberKey: plan.IdentitySigningKey, Registry: registry, RegistryURL: registryURL}); err != nil {
		if !nativeInviteRegistrationDefinitelyRefused(err) {
			return nil, nativeInviteIssuanceRefusal(invite, err)
		}
		if clearErr := awconfig.ClearTeamInviteIssuanceAfterRefusal(awconfig.TeamInviteIssuanceOutcomeInput{InviteID: invite.InviteID, CertificateID: cert.CertificateID}); clearErr != nil {
			return nil, nativeInviteIssuanceRefusal(invite, errors.Join(err, clearErr))
		}
		registerErr := fmt.Errorf("register certificate at registry: %w", err)
		if isAliasConflict(err) {
			// A refused registration does not consume the invite, so it still
			// works with another name.
			registerErr = &plainRefusal{text: nameTakenText(plan.Name, teamID, "--name") + " Your invite is still valid.", err: err}
		}
		return nil, rollbackDefaultAddressClaimAfterCertificateFailure(
			registry,
			registryURL,
			plan.DefaultClaim,
			appliedDefaultClaim,
			registerErr,
		)
	}
	if err := awconfig.ConfirmTeamInviteIssuance(awconfig.TeamInviteIssuanceOutcomeInput{InviteID: invite.InviteID, CertificateID: cert.CertificateID, Now: time.Now()}); err != nil {
		return nil, nativeInviteIssuanceRefusal(invite, err)
	}

	return cert, nil
}

func teamInviteSigningPublicKey(key ed25519.PrivateKey) (ed25519.PublicKey, error) {
	publicKey, valid := key.Public().(ed25519.PublicKey)
	if !valid {
		return nil, errors.New("invite signing key has an invalid public key")
	}
	return publicKey, nil
}

func loadGlobalHostedInviteMaterial(request teamInviteAcceptanceRequest) (workspaceTeamIdentityMaterial, error) {
	identity, signingKey, err := resolveGlobalIdentityForTeamAccept(request.WorkingDir, request.Options.IdentityHome)
	if err != nil {
		return workspaceTeamIdentityMaterial{}, err
	}
	publicKey, err := teamInviteSigningPublicKey(signingKey)
	if err != nil {
		return workspaceTeamIdentityMaterial{}, err
	}
	return workspaceTeamIdentityMaterial{SigningKey: signingKey, PublicKey: publicKey, DIDKey: strings.TrimSpace(identity.DID), StableID: strings.TrimSpace(identity.StableID), IdentityScope: awid.IdentityModeGlobal}, nil
}

type localHostedInviteMaterialRequest struct {
	WorkingDir string
	Home       awconfig.IdentityHome
	Prior      *hostedInviteCreation
}

// A pending attempt must reuse its original key (docs/identity.md:239-245).
func loadLocalHostedInviteMaterial(request localHostedInviteMaterialRequest) (workspaceTeamIdentityMaterial, error) {
	var publicKey ed25519.PublicKey
	var signingKey ed25519.PrivateKey
	if request.Prior != nil {
		keyPath, err := awconfig.IdentityHomePath(request.Home, "signing.key")
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		signingKey, err = awid.LoadSigningKey(keyPath)
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		publicKey, err = teamInviteSigningPublicKey(signingKey)
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
	} else {
		var err error
		publicKey, signingKey, err = hostedAcceptSigningKeyAt(request.WorkingDir, request.Home.Root)
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
	}
	return workspaceTeamIdentityMaterial{SigningKey: signingKey, PublicKey: publicKey, DIDKey: awid.ComputeDIDKey(publicKey), IdentityScope: awid.IdentityModeLocal}, nil
}
