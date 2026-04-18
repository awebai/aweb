package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const (
	doctorCheckIdentityLocalContext        = "identity.local.context"
	doctorCheckIdentityLocalLifetime       = "identity.local.lifetime"
	doctorCheckIdentityLocalDIDKeyFormat   = "identity.local.did_key_format"
	doctorCheckIdentityLocalSigningKey     = "identity.local.signing_key_matches_did"
	doctorCheckIdentityLocalStableID       = "identity.local.stable_id_expected"
	doctorCheckIdentityLocalAddress        = "identity.local.address_expected"
	doctorCheckIdentityLocalRegistrySource = "identity.local.registry_url_source"
	doctorCheckIdentityLocalEphemeralAWID  = "identity.ephemeral.public_registry_not_expected"

	doctorCheckAWIDDIDResolve            = "awid.did.resolve"
	doctorCheckAWIDDIDCurrentKey         = "awid.did.current_key_matches_local"
	doctorCheckAWIDDIDLog                = "awid.did.log_verifies"
	doctorCheckAWIDAddressResolve        = "awid.address.resolve"
	doctorCheckAWIDAddressStableID       = "awid.address.matches_local_stable_id"
	doctorCheckAWIDAddressCurrentKey     = "awid.address.current_key_matches_local"
	doctorCheckAWIDAddressReverseListing = "awid.address.reverse_listing"
)

type doctorIdentityState struct {
	workingDir     string
	identityPath   string
	signingKeyPath string

	identity       *awconfig.WorktreeIdentity
	identityExists bool
	identityErr    error

	did      string
	stableID string
	address  string
	domain   string
	handle   string
	custody  string
	lifetime string

	registryURL       string
	registryURLSource string
	registryURLErr    error

	signingKey    ed25519.PrivateKey
	signingKeyDID string
	signingKeyErr error
}

type doctorRegistryClient interface {
	ResolveKeyAt(ctx context.Context, registryURL, didAW string) (*awid.DidKeyResolution, error)
	GetDIDLog(ctx context.Context, registryURL, didAW string) ([]awid.DidKeyEvidence, error)
	GetNamespaceAddressAtSigned(ctx context.Context, registryURL, domain, name string, signingKey ed25519.PrivateKey) (*awid.RegistryAddress, string, error)
	ListNamespaceAddressesAtSigned(ctx context.Context, registryURL, domain string, signingKey ed25519.PrivateKey) ([]awid.RegistryAddress, string, error)
}

type awidDoctorRegistryClient struct {
	client *awid.RegistryClient
}

func (c awidDoctorRegistryClient) ResolveKeyAt(ctx context.Context, registryURL, didAW string) (*awid.DidKeyResolution, error) {
	return c.client.ResolveKeyAt(ctx, registryURL, didAW)
}

func (c awidDoctorRegistryClient) GetDIDLog(ctx context.Context, registryURL, didAW string) ([]awid.DidKeyEvidence, error) {
	return c.client.GetDIDLog(ctx, registryURL, didAW)
}

func (c awidDoctorRegistryClient) GetNamespaceAddressAtSigned(ctx context.Context, registryURL, domain, name string, signingKey ed25519.PrivateKey) (*awid.RegistryAddress, string, error) {
	address, _, err := c.client.GetNamespaceAddressAtSigned(ctx, registryURL, domain, name, signingKey)
	return address, registryURL, err
}

func (c awidDoctorRegistryClient) ListNamespaceAddressesAtSigned(ctx context.Context, registryURL, domain string, signingKey ed25519.PrivateKey) ([]awid.RegistryAddress, string, error) {
	addresses, _, err := c.client.ListNamespaceAddressesAtSigned(ctx, registryURL, domain, signingKey)
	return addresses, registryURL, err
}

func (r *doctorRunner) runIdentityDoctorChecks() {
	state := collectDoctorIdentityState(r.workingDir)
	r.addIdentityLocalChecks(state)
}

func (r *doctorRunner) runRegistryDoctorChecks() {
	state := collectDoctorIdentityState(r.workingDir)
	r.addRegistryChecks(state)
}

func collectDoctorIdentityState(workingDir string) *doctorIdentityState {
	state := &doctorIdentityState{
		workingDir:     strings.TrimSpace(workingDir),
		identityPath:   filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()),
		signingKeyPath: awconfig.WorktreeSigningKeyPath(workingDir),
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(state.identityPath)
	if err != nil {
		state.identityErr = err
	} else {
		state.identity = identity
		state.identityExists = true
		state.did = strings.TrimSpace(identity.DID)
		state.stableID = strings.TrimSpace(identity.StableID)
		state.address = strings.TrimSpace(identity.Address)
		state.custody = strings.TrimSpace(identity.Custody)
		state.lifetime = strings.TrimSpace(identity.Lifetime)
		if domain, handle, ok := awconfig.CutIdentityAddress(state.address); ok {
			state.domain = domain
			state.handle = handle
		}
		state.setRegistryURL("identity.yaml", identity.RegistryURL)
	}

	if errors.Is(state.identityErr, os.ErrNotExist) {
		state.identityErr = nil
		state.loadIdentityExpectationFromCertificate()
	}

	if envRegistry := strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")); envRegistry != "" {
		state.setRegistryURL("AWID_REGISTRY_URL", envRegistry)
	}

	state.loadSigningKey()
	return state
}

func (s *doctorIdentityState) setRegistryURL(source, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	safeURL, err := sanitizeLocalURLForOutput(raw)
	s.registryURLSource = source
	if err != nil {
		s.registryURL = ""
		s.registryURLErr = err
		return
	}
	s.registryURL = safeURL
	s.registryURLErr = nil
}

func (s *doctorIdentityState) loadIdentityExpectationFromCertificate() {
	workspace, _, err := loadDoctorWorkspaceFromDir(s.workingDir)
	if err != nil {
		return
	}
	membership := workspace.ActiveMembership()
	if membership == nil {
		return
	}
	certPath := resolveWorkspaceCertificatePath(s.workingDir, membership.CertPath)
	if strings.TrimSpace(certPath) == "" {
		return
	}
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		return
	}
	s.did = strings.TrimSpace(cert.MemberDIDKey)
	s.stableID = strings.TrimSpace(cert.MemberDIDAW)
	s.address = strings.TrimSpace(cert.MemberAddress)
	s.lifetime = strings.TrimSpace(cert.Lifetime)
	s.custody = awid.CustodySelf
	if domain, handle, ok := awconfig.CutIdentityAddress(s.address); ok {
		s.domain = domain
		s.handle = handle
	}
}

func (s *doctorIdentityState) loadSigningKey() {
	signingKey, err := awid.LoadSigningKey(s.signingKeyPath)
	if err != nil {
		s.signingKeyErr = err
		return
	}
	s.signingKey = signingKey
	s.signingKeyDID = awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
}

func (r *doctorRunner) addIdentityLocalChecks(state *doctorIdentityState) {
	if state.identityErr != nil {
		r.add(localPathCheck(doctorCheckIdentityLocalContext, doctorStatusFail, state.identityPath, "Local identity context could not be parsed.", "Repair .aw/identity.yaml before relying on identity diagnostics.", map[string]any{"error": state.identityErr.Error()}))
		r.add(blockedLocalCheck(doctorCheckIdentityLocalLifetime, "Identity lifetime requires parsed identity context.", doctorCheckIdentityLocalContext, localPathTarget(state.identityPath)))
		r.add(blockedLocalCheck(doctorCheckIdentityLocalDIDKeyFormat, "Identity did:key requires parsed identity context.", doctorCheckIdentityLocalContext, localPathTarget(state.identityPath)))
		r.add(blockedLocalCheck(doctorCheckIdentityLocalSigningKey, "Signing key comparison requires parsed identity context.", doctorCheckIdentityLocalContext, localPathTarget(state.signingKeyPath)))
		r.add(blockedLocalCheck(doctorCheckIdentityLocalStableID, "Stable ID expectation requires parsed identity context.", doctorCheckIdentityLocalContext, localPathTarget(state.identityPath)))
		r.add(blockedLocalCheck(doctorCheckIdentityLocalAddress, "Address expectation requires parsed identity context.", doctorCheckIdentityLocalContext, localPathTarget(state.identityPath)))
		r.add(blockedLocalCheck(doctorCheckIdentityLocalRegistrySource, "Registry URL source requires parsed identity context.", doctorCheckIdentityLocalContext, localPathTarget(state.identityPath)))
		return
	}
	if strings.TrimSpace(state.lifetime) == awid.LifetimeEphemeral {
		r.add(localCheck(doctorCheckIdentityLocalContext, doctorStatusOK, identityTarget(state), "Ephemeral identity context is available from the active team certificate.", "", map[string]any{"source": "team_certificate"}))
		r.add(localCheck(doctorCheckIdentityLocalLifetime, doctorStatusOK, identityTarget(state), "Identity lifetime is ephemeral.", "", map[string]any{"lifetime": awid.LifetimeEphemeral}))
		r.addIdentityDIDFormatCheck(state)
		r.addIdentitySigningKeyCheck(state)
		r.add(localCheck(doctorCheckIdentityLocalStableID, doctorStatusInfo, identityTarget(state), "Ephemeral identity does not require a did:aw stable_id.", "", map[string]any{"expected": false}))
		r.add(localCheck(doctorCheckIdentityLocalAddress, doctorStatusInfo, identityTarget(state), "Ephemeral identity does not require a public address.", "", map[string]any{"expected": false}))
		r.add(localCheck(doctorCheckIdentityLocalRegistrySource, doctorStatusInfo, nil, "Ephemeral identity does not require an awid registry URL.", "", map[string]any{"expected": false}))
		r.add(localCheck(doctorCheckIdentityLocalEphemeralAWID, doctorStatusOK, identityTarget(state), "Public awid registration is not expected for ephemeral identity.", "", nil))
		return
	}

	if !state.identityExists {
		if strings.TrimSpace(state.lifetime) == awid.LifetimePersistent {
			r.add(localPathCheck(doctorCheckIdentityLocalContext, doctorStatusFail, state.identityPath, "Persistent identity.yaml is missing.", "Restore .aw/identity.yaml before using persistent identity or awid registry diagnostics.", map[string]any{"state": "missing", "expected_lifetime": awid.LifetimePersistent, "source": "team_certificate"}))
			r.add(localCheck(doctorCheckIdentityLocalLifetime, doctorStatusOK, identityTarget(state), "Active team certificate expects persistent identity.", "", map[string]any{"lifetime": awid.LifetimePersistent, "source": "team_certificate"}))
			r.addIdentityDIDFormatCheck(state)
			r.addIdentitySigningKeyCheck(state)
			r.add(localPathCheck(doctorCheckIdentityLocalStableID, doctorStatusBlocked, state.identityPath, "Stable ID expectation requires persistent identity.yaml.", "Restore .aw/identity.yaml before using awid registry diagnostics.", map[string]any{"prerequisite": doctorCheckIdentityLocalContext}))
			r.add(localPathCheck(doctorCheckIdentityLocalAddress, doctorStatusBlocked, state.identityPath, "Address expectation requires persistent identity.yaml.", "Restore .aw/identity.yaml before using awid address diagnostics.", map[string]any{"prerequisite": doctorCheckIdentityLocalContext}))
			r.add(localPathCheck(doctorCheckIdentityLocalRegistrySource, doctorStatusBlocked, state.identityPath, "Registry URL source requires persistent identity.yaml or AWID_REGISTRY_URL.", "Restore .aw/identity.yaml or set AWID_REGISTRY_URL.", map[string]any{"prerequisite": doctorCheckIdentityLocalContext}))
			return
		}
		r.add(localPathCheck(doctorCheckIdentityLocalContext, doctorStatusInfo, state.identityPath, "No identity.yaml was found.", "Run `aw init` or `aw id create` when a persistent identity is expected.", map[string]any{"state": "missing"}))
		r.add(localPathCheck(doctorCheckIdentityLocalLifetime, doctorStatusInfo, state.identityPath, "Identity lifetime is unavailable because no identity context was found.", "", map[string]any{"reason": "no_identity_context"}))
		r.add(localPathCheck(doctorCheckIdentityLocalDIDKeyFormat, doctorStatusInfo, state.identityPath, "Identity did:key is unavailable because no identity context was found.", "", map[string]any{"reason": "no_identity_context"}))
		r.add(localPathCheck(doctorCheckIdentityLocalSigningKey, doctorStatusInfo, state.signingKeyPath, "Signing key comparison is unavailable because no identity context was found.", "", map[string]any{"reason": "no_identity_context"}))
		r.add(localPathCheck(doctorCheckIdentityLocalStableID, doctorStatusInfo, state.identityPath, "Stable ID expectation is unavailable because no identity context was found.", "", map[string]any{"reason": "no_identity_context"}))
		r.add(localPathCheck(doctorCheckIdentityLocalAddress, doctorStatusInfo, state.identityPath, "Address expectation is unavailable because no identity context was found.", "", map[string]any{"reason": "no_identity_context"}))
		r.add(localPathCheck(doctorCheckIdentityLocalRegistrySource, doctorStatusInfo, state.identityPath, "Registry URL source is unavailable because no identity context was found.", "", map[string]any{"reason": "no_identity_context"}))
		return
	}

	r.add(localPathCheck(doctorCheckIdentityLocalContext, doctorStatusOK, state.identityPath, "Persistent identity.yaml parsed successfully.", "", map[string]any{"source": awconfig.DefaultWorktreeIdentityRelativePath()}))
	switch state.lifetime {
	case awid.LifetimePersistent:
		r.add(localCheck(doctorCheckIdentityLocalLifetime, doctorStatusOK, identityTarget(state), "Identity lifetime is persistent.", "", map[string]any{"lifetime": state.lifetime}))
	case "":
		r.add(localPathCheck(doctorCheckIdentityLocalLifetime, doctorStatusFail, state.identityPath, "Persistent identity lifetime is missing.", "Repair identity.yaml with a supported lifetime.", nil))
	default:
		r.add(localPathCheck(doctorCheckIdentityLocalLifetime, doctorStatusFail, state.identityPath, "Identity lifetime is unknown.", "Repair identity.yaml with a supported lifetime.", map[string]any{"lifetime": state.lifetime}))
	}
	r.addIdentityDIDFormatCheck(state)
	r.addIdentitySigningKeyCheck(state)
	r.addPersistentStableIDCheck(state)
	r.addPersistentAddressCheck(state)
	r.addRegistryURLSourceCheck(state)
}

func (r *doctorRunner) addIdentityDIDFormatCheck(state *doctorIdentityState) {
	if strings.TrimSpace(state.did) == "" {
		r.add(localCheck(doctorCheckIdentityLocalDIDKeyFormat, doctorStatusFail, identityTarget(state), "Identity did:key is missing.", "Repair local identity state before using awid diagnostics.", nil))
		return
	}
	if _, err := awid.ExtractPublicKey(state.did); err != nil {
		r.add(localCheck(doctorCheckIdentityLocalDIDKeyFormat, doctorStatusFail, identityTarget(state), "Identity did:key is invalid.", "Repair local identity state with a valid did:key.", map[string]any{"error": "invalid_did_key"}))
		return
	}
	r.add(localCheck(doctorCheckIdentityLocalDIDKeyFormat, doctorStatusOK, identityTarget(state), "Identity did:key is syntactically valid.", "", map[string]any{"did_key": state.did}))
}

func (r *doctorRunner) addIdentitySigningKeyCheck(state *doctorIdentityState) {
	if state.custody != "" && state.custody != awid.CustodySelf {
		r.add(localPathCheck(doctorCheckIdentityLocalSigningKey, doctorStatusBlocked, state.signingKeyPath, "Local signing key check is not applicable to non-self-custodial identity.", "", map[string]any{"custody": state.custody}))
		return
	}
	if state.signingKeyErr != nil {
		status := doctorStatusFail
		message := "Local signing key could not be loaded."
		if errors.Is(state.signingKeyErr, os.ErrNotExist) {
			message = "Local signing key is missing."
		}
		r.add(localPathCheck(doctorCheckIdentityLocalSigningKey, status, state.signingKeyPath, message, "Restore .aw/signing.key or reconnect this identity.", map[string]any{"error": safeLocalKeyError(state.signingKeyErr)}))
		return
	}
	if state.signingKeyDID != strings.TrimSpace(state.did) {
		r.add(localCheck(doctorCheckIdentityLocalSigningKey, doctorStatusFail, &doctorTarget{Type: "did", ID: state.signingKeyDID}, "Local signing key did:key does not match identity did.", "Restore the signing key that belongs to this identity before using awid operations.", map[string]any{"signing_key_did": state.signingKeyDID, "identity_did": strings.TrimSpace(state.did)}))
		return
	}
	r.add(localCheck(doctorCheckIdentityLocalSigningKey, doctorStatusOK, &doctorTarget{Type: "did", ID: state.signingKeyDID}, "Local signing key matches identity did.", "", map[string]any{"did_key": state.signingKeyDID}))
}

func (r *doctorRunner) addPersistentStableIDCheck(state *doctorIdentityState) {
	if strings.TrimSpace(state.stableID) == "" {
		r.add(localPathCheck(doctorCheckIdentityLocalStableID, doctorStatusFail, state.identityPath, "Persistent identity stable_id is missing.", "Repair identity.yaml or re-register the persistent identity under caller authority.", nil))
		return
	}
	if !strings.HasPrefix(state.stableID, "did:aw:") {
		r.add(localPathCheck(doctorCheckIdentityLocalStableID, doctorStatusFail, state.identityPath, "Persistent identity stable_id is not a did:aw identifier.", "Repair identity.yaml with a valid did:aw stable identifier.", nil))
		return
	}
	r.add(localCheck(doctorCheckIdentityLocalStableID, doctorStatusOK, &doctorTarget{Type: "did", ID: state.stableID}, "Persistent identity stable_id is present.", "", map[string]any{"stable_id": state.stableID}))
}

func (r *doctorRunner) addPersistentAddressCheck(state *doctorIdentityState) {
	if strings.TrimSpace(state.address) == "" {
		r.add(localPathCheck(doctorCheckIdentityLocalAddress, doctorStatusFail, state.identityPath, "Persistent identity address is missing.", "Repair identity.yaml with the registered address before using address diagnostics.", nil))
		return
	}
	if state.domain == "" || state.handle == "" {
		r.add(localPathCheck(doctorCheckIdentityLocalAddress, doctorStatusFail, state.identityPath, "Persistent identity address is malformed.", "Use the canonical domain/name address form.", map[string]any{"address": state.address}))
		return
	}
	r.add(localCheck(doctorCheckIdentityLocalAddress, doctorStatusOK, &doctorTarget{Type: "address", ID: state.address}, "Persistent identity address is present.", "", map[string]any{"address": state.address}))
}

func (r *doctorRunner) addRegistryURLSourceCheck(state *doctorIdentityState) {
	if state.registryURLErr != nil {
		r.add(localCheck(doctorCheckIdentityLocalRegistrySource, doctorStatusFail, nil, "Explicit awid registry URL is invalid.", "Repair identity registry_url or AWID_REGISTRY_URL.", map[string]any{"source": state.registryURLSource, "error": state.registryURLErr.Error()}))
		return
	}
	if strings.TrimSpace(state.registryURL) == "" {
		r.add(localCheck(doctorCheckIdentityLocalRegistrySource, doctorStatusBlocked, nil, "No explicit awid registry URL is configured.", "Set identity registry_url or AWID_REGISTRY_URL; doctor will not use public namespace discovery as ownership proof.", map[string]any{"reason": "no_explicit_registry_url"}))
		return
	}
	r.add(localCheck(doctorCheckIdentityLocalRegistrySource, doctorStatusOK, nil, "Explicit awid registry URL is available.", "", map[string]any{"source": state.registryURLSource, "registry_url": state.registryURL}))
}

func (r *doctorRunner) addRegistryChecks(state *doctorIdentityState) {
	awidCheckIDs := []string{
		doctorCheckAWIDDIDResolve,
		doctorCheckAWIDDIDCurrentKey,
		doctorCheckAWIDDIDLog,
		doctorCheckAWIDAddressResolve,
		doctorCheckAWIDAddressStableID,
		doctorCheckAWIDAddressCurrentKey,
		doctorCheckAWIDAddressReverseListing,
	}
	if strings.TrimSpace(state.lifetime) == awid.LifetimeEphemeral {
		for _, id := range awidCheckIDs {
			r.add(awidCheck(id, doctorStatusInfo, "Public awid registration is not expected for ephemeral identity.", "", map[string]any{"reason": "ephemeral_not_applicable"}))
		}
		return
	}
	if !state.identityExists && strings.TrimSpace(state.lifetime) == "" {
		for _, id := range awidCheckIDs {
			r.add(awidCheck(id, doctorStatusInfo, "No identity context is available for awid registry diagnostics.", "", map[string]any{"reason": "no_identity_context"}))
		}
		return
	}
	if r.opts.Mode != doctorModeOnline {
		reason := "auto_mode"
		if r.opts.Mode == doctorModeOffline {
			reason = "offline_mode"
		}
		for _, id := range awidCheckIDs {
			r.add(awidCheck(id, doctorStatusUnknown, "Online awid check was skipped.", "Run `aw doctor registry --online` to contact awid.", map[string]any{"skipped": true, "reason": reason}))
		}
		return
	}
	if prereq := registryPreconditionFailure(state); prereq != "" {
		for _, id := range awidCheckIDs {
			r.add(awidCheck(id, doctorStatusBlocked, "Online awid check is blocked by local identity preconditions.", "Resolve local identity checks first.", map[string]any{"reason": prereq}))
		}
		return
	}

	client := awidDoctorRegistryClient{client: awid.NewAWIDRegistryClient(nil, nil)}
	r.runOnlineRegistryChecks(state, client)
}

func (r *doctorRunner) runOnlineRegistryChecks(state *doctorIdentityState, client doctorRegistryClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolution, resolveOK, blockedPrerequisite := r.addDIDResolveChecks(ctx, state, client)
	if !resolveOK {
		message := "DID/address checks require a resolved persistent did:aw."
		nextStep := "Resolve awid.did.resolve first."
		if blockedPrerequisite == doctorCheckAWIDDIDCurrentKey {
			message = "DID/address checks require awid current did:key to match local identity."
			nextStep = "Resolve awid.did.current_key_matches_local first."
		}
		r.add(awidCheck(doctorCheckAWIDDIDLog, doctorStatusBlocked, message, nextStep, map[string]any{"prerequisite": blockedPrerequisite}))
		r.addBlockedAddressChecks(message, blockedPrerequisite)
		return
	}
	r.addDIDLogCheck(ctx, state, client, resolution)
	r.addAddressChecks(ctx, state, client)
}

func (r *doctorRunner) addDIDResolveChecks(ctx context.Context, state *doctorIdentityState, client doctorRegistryClient) (*awid.DidKeyResolution, bool, string) {
	resolution, err := client.ResolveKeyAt(ctx, state.registryURL, state.stableID)
	if err != nil {
		statusCode, hasStatus := doctorRegistryStatusCode(err)
		switch {
		case hasStatus && statusCode == http.StatusNotFound:
			r.add(awidCheck(doctorCheckAWIDDIDResolve, doctorStatusFail, "Persistent did:aw was not found in awid.", "Register or repair this persistent identity under caller authority; do not replace it automatically.", map[string]any{"reason": "did_not_found", "registry_url": state.registryURL, "did_aw": state.stableID}))
		case hasStatus && statusCode == http.StatusForbidden:
			r.add(awidCheck(doctorCheckAWIDDIDResolve, doctorStatusBlocked, "Caller lacks visibility to resolve this did:aw.", "Retry with the identity that has visibility or escalate with the support bundle.", map[string]any{"reason": "caller_lacks_visibility", "status_code": statusCode, "registry_url": state.registryURL}))
		case hasStatus && statusCode >= 500:
			r.add(awidCheck(doctorCheckAWIDDIDResolve, doctorStatusUnknown, "awid is unavailable for did:aw resolution.", "Retry later or include this support bundle with the registry status.", map[string]any{"reason": "awid_unavailable", "status_code": statusCode, "registry_url": state.registryURL}))
		default:
			r.add(awidCheck(doctorCheckAWIDDIDResolve, doctorStatusUnknown, "awid did:aw resolution failed.", "Retry later or include this support bundle with the registry status.", map[string]any{"reason": "awid_unavailable", "registry_url": state.registryURL}))
		}
		r.add(awidCheck(doctorCheckAWIDDIDCurrentKey, doctorStatusBlocked, "Current-key comparison requires a resolved did:aw.", "Resolve awid.did.resolve first.", map[string]any{"prerequisite": doctorCheckAWIDDIDResolve}))
		return nil, false, doctorCheckAWIDDIDResolve
	}
	if strings.TrimSpace(resolution.DIDAW) != "" && strings.TrimSpace(resolution.DIDAW) != state.stableID {
		r.add(awidCheck(doctorCheckAWIDDIDResolve, doctorStatusFail, "awid returned a different did:aw than requested.", "Escalate this registry inconsistency; do not mutate local identity automatically.", map[string]any{"reason": "did_aw_mismatch", "expected_did_aw": state.stableID, "registry_did_aw": strings.TrimSpace(resolution.DIDAW)}))
		r.add(awidCheck(doctorCheckAWIDDIDCurrentKey, doctorStatusBlocked, "Current-key comparison requires coherent did:aw resolution.", "Resolve awid.did.resolve first.", map[string]any{"prerequisite": doctorCheckAWIDDIDResolve}))
		return resolution, false, doctorCheckAWIDDIDResolve
	}
	r.add(awidCheck(doctorCheckAWIDDIDResolve, doctorStatusOK, "Persistent did:aw resolves at awid.", "", map[string]any{"registry_url": state.registryURL, "did_aw": state.stableID}))
	if strings.TrimSpace(resolution.CurrentDIDKey) != strings.TrimSpace(state.did) {
		r.add(awidCheck(doctorCheckAWIDDIDCurrentKey, doctorStatusFail, "awid current did:key does not match local identity did.", "Escalate key mismatch; do not replace identity automatically.", map[string]any{"local_did": state.did, "registry_current_did_key": strings.TrimSpace(resolution.CurrentDIDKey)}))
		return resolution, false, doctorCheckAWIDDIDCurrentKey
	}
	r.add(awidCheck(doctorCheckAWIDDIDCurrentKey, doctorStatusOK, "awid current did:key matches local identity did.", "", map[string]any{"did_key": state.did}))
	return resolution, true, ""
}

func (r *doctorRunner) addDIDLogCheck(ctx context.Context, state *doctorIdentityState, client doctorRegistryClient, resolution *awid.DidKeyResolution) {
	entries, err := client.GetDIDLog(ctx, state.registryURL, state.stableID)
	if err != nil {
		statusCode, hasStatus := doctorRegistryStatusCode(err)
		if hasStatus && statusCode >= 500 {
			r.add(awidCheck(doctorCheckAWIDDIDLog, doctorStatusUnknown, "awid is unavailable for DID log verification.", "Retry later or include this support bundle with the registry status.", map[string]any{"reason": "awid_unavailable", "status_code": statusCode}))
			return
		}
		r.add(awidCheck(doctorCheckAWIDDIDLog, doctorStatusUnknown, "DID log verification could not be completed.", "Retry later or include this support bundle with the registry status.", map[string]any{"reason": "awid_unavailable"}))
		return
	}
	head, err := awid.VerifyDidLogEntries(state.stableID, entries, time.Now().UTC())
	if err != nil {
		r.add(awidCheck(doctorCheckAWIDDIDLog, doctorStatusFail, "DID audit log verification failed.", "Escalate the registry log inconsistency; do not mutate identity automatically.", map[string]any{"reason": "did_log_invalid"}))
		return
	}
	if head == nil || strings.TrimSpace(head.CurrentDIDKey) == "" {
		r.add(awidCheck(doctorCheckAWIDDIDLog, doctorStatusFail, "DID audit log is missing a current key head.", "Escalate the registry log inconsistency.", map[string]any{"reason": "did_log_missing_head"}))
		return
	}
	if resolution != nil && strings.TrimSpace(resolution.CurrentDIDKey) != "" && strings.TrimSpace(head.CurrentDIDKey) != strings.TrimSpace(resolution.CurrentDIDKey) {
		r.add(awidCheck(doctorCheckAWIDDIDLog, doctorStatusFail, "DID audit log head does not match resolved current did:key.", "Escalate the registry log inconsistency.", map[string]any{"reason": "did_log_current_key_mismatch"}))
		return
	}
	r.add(awidCheck(doctorCheckAWIDDIDLog, doctorStatusOK, "DID audit log verifies.", "", map[string]any{"entry_count": len(entries), "current_did_key": strings.TrimSpace(head.CurrentDIDKey)}))
}

func (r *doctorRunner) addAddressChecks(ctx context.Context, state *doctorIdentityState, client doctorRegistryClient) {
	if strings.TrimSpace(state.custody) != awid.CustodySelf || state.signingKey == nil {
		r.addBlockedAddressChecks("Visibility-sensitive address checks require self custody and the local signing key.", doctorCheckIdentityLocalSigningKey)
		return
	}
	if state.domain == "" || state.handle == "" {
		r.addBlockedAddressChecks("Address checks require a local domain/name address.", doctorCheckIdentityLocalAddress)
		return
	}

	address, _, err := client.GetNamespaceAddressAtSigned(ctx, state.registryURL, state.domain, state.handle, state.signingKey)
	if err != nil {
		statusCode, hasStatus := doctorRegistryStatusCode(err)
		switch {
		case hasStatus && statusCode == http.StatusNotFound:
			r.add(awidCheck(doctorCheckAWIDAddressResolve, doctorStatusWarn, "Persistent address was not found in awid.", "Register or repair the address under caller authority; do not replace identity automatically.", map[string]any{"reason": "address_not_found", "address": state.address}))
		case hasStatus && statusCode == http.StatusForbidden:
			r.add(awidCheck(doctorCheckAWIDAddressResolve, doctorStatusBlocked, "Caller lacks visibility to read this address.", "Retry with the identity that has visibility or escalate with the support bundle.", map[string]any{"reason": "caller_lacks_visibility", "status_code": statusCode}))
			r.add(awidCheck(doctorCheckAWIDAddressStableID, doctorStatusBlocked, "Address stable-id comparison requires resolved address data.", "Resolve awid.address.resolve first.", map[string]any{"prerequisite": doctorCheckAWIDAddressResolve}))
			r.add(awidCheck(doctorCheckAWIDAddressCurrentKey, doctorStatusBlocked, "Address current-key comparison requires resolved address data.", "Resolve awid.address.resolve first.", map[string]any{"prerequisite": doctorCheckAWIDAddressResolve}))
			r.add(awidCheck(doctorCheckAWIDAddressReverseListing, doctorStatusBlocked, "Caller lacks visibility to read this address; reverse listing was not attempted.", "Retry with the identity that has visibility or escalate with the support bundle.", map[string]any{"reason": "caller_lacks_visibility", "prerequisite": doctorCheckAWIDAddressResolve}))
			return
		case hasStatus && statusCode >= 500:
			r.add(awidCheck(doctorCheckAWIDAddressResolve, doctorStatusUnknown, "awid is unavailable for address lookup.", "Retry later.", map[string]any{"reason": "awid_unavailable", "status_code": statusCode}))
		default:
			r.add(awidCheck(doctorCheckAWIDAddressResolve, doctorStatusUnknown, "Address lookup could not be completed.", "Retry later.", map[string]any{"reason": "awid_unavailable"}))
		}
		r.add(awidCheck(doctorCheckAWIDAddressStableID, doctorStatusBlocked, "Address stable-id comparison requires resolved address data.", "Resolve awid.address.resolve first.", map[string]any{"prerequisite": doctorCheckAWIDAddressResolve}))
		r.add(awidCheck(doctorCheckAWIDAddressCurrentKey, doctorStatusBlocked, "Address current-key comparison requires resolved address data.", "Resolve awid.address.resolve first.", map[string]any{"prerequisite": doctorCheckAWIDAddressResolve}))
		r.addAddressReverseListingCheck(ctx, state, client)
		return
	}

	r.add(awidCheck(doctorCheckAWIDAddressResolve, doctorStatusOK, "Persistent address resolves under caller authority.", "", map[string]any{"address": state.address}))
	if strings.TrimSpace(address.DIDAW) != state.stableID {
		r.add(awidCheck(doctorCheckAWIDAddressStableID, doctorStatusWarn, "Registered address points at a different did:aw.", "Repair address registration under namespace authority; do not replace identity automatically.", map[string]any{"local_did_aw": state.stableID, "address_did_aw": strings.TrimSpace(address.DIDAW)}))
	} else {
		r.add(awidCheck(doctorCheckAWIDAddressStableID, doctorStatusOK, "Registered address did:aw matches local stable_id.", "", map[string]any{"did_aw": state.stableID}))
	}
	if strings.TrimSpace(address.CurrentDIDKey) != "" && strings.TrimSpace(address.CurrentDIDKey) != state.did {
		r.add(awidCheck(doctorCheckAWIDAddressCurrentKey, doctorStatusFail, "Registered address current did:key does not match local identity did.", "Escalate key mismatch; repair registry state under authority only.", map[string]any{"local_did": state.did, "address_current_did_key": strings.TrimSpace(address.CurrentDIDKey)}))
	} else {
		r.add(awidCheck(doctorCheckAWIDAddressCurrentKey, doctorStatusOK, "Registered address current did:key matches local identity did.", "", map[string]any{"did_key": state.did}))
	}
	r.addAddressReverseListingCheck(ctx, state, client)
}

func (r *doctorRunner) addAddressReverseListingCheck(ctx context.Context, state *doctorIdentityState, client doctorRegistryClient) {
	if strings.TrimSpace(state.custody) != awid.CustodySelf || state.signingKey == nil || state.domain == "" {
		r.add(awidCheck(doctorCheckAWIDAddressReverseListing, doctorStatusBlocked, "Reverse address listing requires self custody, signing key, and address domain.", "Resolve local identity preconditions first.", map[string]any{"prerequisite": doctorCheckIdentityLocalSigningKey}))
		return
	}
	addresses, _, err := client.ListNamespaceAddressesAtSigned(ctx, state.registryURL, state.domain, state.signingKey)
	if err != nil {
		statusCode, hasStatus := doctorRegistryStatusCode(err)
		switch {
		case hasStatus && statusCode == http.StatusForbidden:
			r.add(awidCheck(doctorCheckAWIDAddressReverseListing, doctorStatusBlocked, "Caller lacks visibility to list namespace addresses.", "Retry with the identity that has visibility or escalate with the support bundle.", map[string]any{"reason": "caller_lacks_visibility", "status_code": statusCode}))
		case hasStatus && statusCode >= 500:
			r.add(awidCheck(doctorCheckAWIDAddressReverseListing, doctorStatusUnknown, "awid is unavailable for reverse address listing.", "Retry later.", map[string]any{"reason": "awid_unavailable", "status_code": statusCode}))
		default:
			r.add(awidCheck(doctorCheckAWIDAddressReverseListing, doctorStatusUnknown, "Reverse address listing could not be completed.", "Retry later.", map[string]any{"reason": "awid_unavailable"}))
		}
		return
	}
	matching := make([]string, 0, 1)
	for _, address := range addresses {
		full := strings.TrimSpace(address.Domain) + "/" + strings.TrimSpace(address.Name)
		if strings.TrimSpace(address.DIDAW) == state.stableID || strings.TrimSpace(address.CurrentDIDKey) == state.did {
			matching = append(matching, full)
		}
	}
	if len(matching) == 0 {
		r.add(awidCheck(doctorCheckAWIDAddressReverseListing, doctorStatusWarn, "No registered address was visible for the local did:aw.", "Repair address registration under caller authority; do not replace identity automatically.", map[string]any{"reason": "no_registered_address_for_did"}))
		return
	}
	for _, address := range matching {
		if address == state.address {
			r.add(awidCheck(doctorCheckAWIDAddressReverseListing, doctorStatusOK, "Reverse address listing includes the local address.", "", map[string]any{"address": state.address}))
			return
		}
	}
	r.add(awidCheck(doctorCheckAWIDAddressReverseListing, doctorStatusWarn, "Local did:aw is registered under a different visible address.", "Repair address registration under namespace authority; do not replace identity automatically.", map[string]any{"local_address": state.address, "registered_addresses": matching}))
}

func (r *doctorRunner) addBlockedAddressChecks(message, prerequisite string) {
	for _, id := range []string{
		doctorCheckAWIDAddressResolve,
		doctorCheckAWIDAddressStableID,
		doctorCheckAWIDAddressCurrentKey,
		doctorCheckAWIDAddressReverseListing,
	} {
		r.add(awidCheck(id, doctorStatusBlocked, message, "Resolve the prerequisite identity state first.", map[string]any{"prerequisite": prerequisite}))
	}
}

func registryPreconditionFailure(state *doctorIdentityState) string {
	switch {
	case !state.identityExists && strings.TrimSpace(state.lifetime) == awid.LifetimePersistent:
		return "missing_identity_context"
	case state.registryURLErr != nil:
		return "invalid_registry_url"
	case strings.TrimSpace(state.registryURL) == "":
		return "no_explicit_registry_url"
	case strings.TrimSpace(state.lifetime) != awid.LifetimePersistent:
		return "persistent_identity_required"
	case strings.TrimSpace(state.did) == "":
		return "missing_did_key"
	case strings.TrimSpace(state.stableID) == "":
		return "missing_did_aw"
	case !strings.HasPrefix(strings.TrimSpace(state.stableID), "did:aw:"):
		return "invalid_did_aw"
	}
	if _, err := awid.ExtractPublicKey(state.did); err != nil {
		return "invalid_did_key"
	}
	return ""
}

func identityTarget(state *doctorIdentityState) *doctorTarget {
	if state == nil {
		return nil
	}
	if strings.TrimSpace(state.stableID) != "" {
		return &doctorTarget{Type: "did", ID: strings.TrimSpace(state.stableID)}
	}
	if strings.TrimSpace(state.did) != "" {
		return &doctorTarget{Type: "did", ID: strings.TrimSpace(state.did)}
	}
	return nil
}

func awidCheck(id string, status doctorStatus, message, nextStep string, detail map[string]any) doctorCheck {
	return doctorCheck{
		ID:            id,
		Status:        status,
		Source:        doctorSourceAwid,
		Authority:     doctorAuthorityCaller,
		Authoritative: false,
		Message:       message,
		Detail:        detail,
		NextStep:      nextStep,
	}
}

func doctorRegistryStatusCode(err error) (int, bool) {
	var registryErr *awid.RegistryError
	if errors.As(err, &registryErr) {
		return registryErr.StatusCode, true
	}
	if code, ok := awid.HTTPStatusCode(err); ok {
		return code, true
	}
	return 0, false
}

func safeLocalKeyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, os.ErrNotExist) {
		return "missing"
	}
	return "unreadable_or_invalid"
}
