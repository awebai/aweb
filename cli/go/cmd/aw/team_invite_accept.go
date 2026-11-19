package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/awebai/aw/awid"
)

type teamInviteAcceptanceRequest struct {
	WorkingDir string
	Options    teamAcceptInviteOptions
}

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
	Plan        *teamMemberEnrollmentPlan
	Registry    *awid.RegistryClient
	RegistryURL string
}

func claimNativeInviteDefaultAddress(ctx context.Context, request nativeInviteDefaultClaimRequest) (*awid.AtomicAddressClaimResult, error) {
	plan, registry, registryURL := request.Plan, request.Registry, request.RegistryURL
	var appliedDefaultClaim *awid.AtomicAddressClaimResult
	var err error
	if plan.DefaultClaim != nil {
		if _, err := registry.ClaimIdentityAddressAt(ctx, registryURL, *plan.DefaultClaim); err != nil {
			return nil, idAddressClaimAtomicError(plan.MemberAddress, registryURL, err)
		}
		plan.DefaultClaim.DryRun = false
		appliedDefaultClaim, err = registry.ClaimIdentityAddressAt(ctx, registryURL, *plan.DefaultClaim)
		if err != nil {
			return nil, idAddressClaimAtomicError(plan.MemberAddress, registryURL, err)
		}
	}

	return appliedDefaultClaim, nil
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
	var err error
	var resp *awid.SpawnAcceptInviteResponse
	if creation.ResponseJSON != "" {
		resp = &awid.SpawnAcceptInviteResponse{}
		err = json.Unmarshal([]byte(creation.ResponseJSON), resp)
	} else {
		attempted := true
		creation.AcceptAttempted = &attempted
		if err := creation.save(recoveryPath); err != nil {
			return nil, err
		}
		resp, err = client.AcceptSpawnInvite(ctx, req)
	}
	if err != nil {
		return nil, fmt.Errorf("accept hosted team invite: %w", err)
	}
	return resp, nil
}
