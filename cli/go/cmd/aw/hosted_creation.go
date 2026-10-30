package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Each constructor retains this alongside its original private child key. The
// canonical response is retained before registration, so a retry cannot replace
// a certificate or its registration arguments after a partial remote effect.
type hostedIDTreeRecovery struct {
	Mode                  string         `json:"mode,omitempty" yaml:"mode,omitempty"`
	RequestID             string         `json:"request_id" yaml:"request_id"`
	Domain                string         `json:"domain,omitempty" yaml:"domain,omitempty"`
	Parent                map[string]any `json:"parent,omitempty" yaml:"parent,omitempty"`
	NativeChainHeader     string         `json:"native_chain_header,omitempty" yaml:"native_chain_header,omitempty"`
	ResponseFieldsPresent *bool          `json:"response_fields_present,omitempty" yaml:"response_fields_present,omitempty"`
	ResponseJSON          string         `json:"response_json,omitempty" yaml:"response_json,omitempty"`
}

func newHostedIDTreeRecovery(association hostedIdentityContext) (*hostedIDTreeRecovery, error) {
	id, err := awid.GenerateUUID4()
	if err != nil {
		return nil, err
	}
	tree := &hostedIDTreeRecovery{RequestID: id, Domain: association.Domain}
	if association.ParentID != "" {
		tree.Parent = map[string]any{"kind": association.ParentKind, "id": association.ParentID}
	}
	return tree, nil
}

func (tree *hostedIDTreeRecovery) request(chain map[string]any) *awid.IDTreeCreationRequest {
	if tree == nil || tree.Domain == "" {
		return nil
	}
	return &awid.IDTreeCreationRequest{Mode: tree.Mode, V: 1, RequestID: tree.RequestID, Domain: tree.Domain, Parent: tree.Parent, IDChain: chain}
}

func (tree *hostedIDTreeRecovery) retainResponse(response awid.IDTreeCreationResponse) error {
	if response.IDChain == nil && response.RegistrationRequest != nil {
		return errors.New("creation response requests registration without a chain")
	}
	if tree.ResponseFieldsPresent != nil && *tree.ResponseFieldsPresent != response.FieldsPresent {
		return errors.New("creation retry changed the advertised attribution protocol")
	}
	raw, err := canonicalCreationResponse(response)
	if err != nil {
		return err
	}
	if tree.ResponseJSON != "" && tree.ResponseJSON != raw {
		return errors.New("creation retry returned a different chain or registration request; retain the original recovery state")
	}
	present := response.FieldsPresent
	tree.ResponseFieldsPresent = &present
	tree.ResponseJSON = raw
	return nil
}

func loadHostedIdentityRecovery(path string) (*hostedIdentityRecovery, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state hostedIdentityRecovery
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state.Version != 1 || state.IDTree == nil || state.IDTree.RequestID == "" {
		return nil, errors.New("invalid hosted creation recovery")
	}
	return &state, nil
}

func saveHostedIdentityRecovery(path string, state *hostedIdentityRecovery) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(path, raw)
}

// Marshal structs through the ordinary JSON encoder before canonicalizing; the
// canonicalizer accepts JSON values rather than Go structs.
func canonicalCreationResponse(response awid.IDTreeCreationResponse) (string, error) {
	raw, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	return awid.CanonicalJSONValue(value)
}

type hostedHumanParent struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
}

func selectHostedPersonParent(account cliAuthAccount, selected string, root bool) (*hostedHumanParent, error) {
	if root {
		return nil, usageError("person creation requires a registered human parent; --root-parent cannot replace it")
	}
	if account.HumanIdentities == nil {
		return nil, errors.New("registered human evidence unavailable; retry after account verification")
	}
	if len(account.HumanIdentities) == 0 {
		return nil, usageError("register a human for this account before creating an attributed agent")
	}
	var matches []hostedHumanParent
	for _, human := range account.HumanIdentities {
		if !strings.HasPrefix(human.ID, "did:aw:") || human.Domain == "" {
			return nil, errors.New("malformed registered human evidence")
		}
		if selected == "" || human.ID == selected {
			matches = append(matches, human)
		}
	}
	if len(matches) != 1 {
		return nil, usageError("select exactly one registered account human with --human-parent")
	}
	return &matches[0], nil
}

func requireLegacyHostedOwner(ctx context.Context, owner *hostedOwnerAuthority, registry *awid.RegistryClient) error {
	if owner.stableID == "" {
		return nil
	}
	origin := owner.registryURL
	if origin == "" {
		origin = registry.DefaultRegistryURL
	}
	key, err := registry.ResolveKeyAt(ctx, origin, owner.stableID)
	if err != nil {
		return fmt.Errorf("owner enrollment unavailable: %w", err)
	}
	if key == nil || key.DIDAW != owner.stableID || key.CurrentDIDKey != owner.did {
		return errors.New("owner enrollment does not match the selected stable identity and current key")
	}
	switch key.IDTreeEnrollment(time.Now()).State {
	case "not_enrolled":
		return nil
	case "enrolled":
		return usageError("owner is enrolled; install its chain before creating a child")
	default:
		return errors.New("owner enrollment unavailable; absence of a local chain does not establish a legacy owner")
	}
}

// The selected native owner supplies its own verified agent ancestry. A missing
// file is only legacy after current key-route enrollment proves that omission
// is permitted; malformed or revoked ancestry never falls through to legacy.
func hostedOwnerIssuer(ctx context.Context, workingDir string, owner *hostedOwnerAuthority, registry *awid.RegistryClient, resolver awid.TXTResolver) (*selectedChildIssuer, error) {
	chain, err := awconfig.LoadInstalledIDChain(owner.home)
	if err != nil {
		return nil, err
	}
	if chain == nil {
		return nil, requireLegacyHostedOwner(ctx, owner, registry)
	}
	certificates := chain.Bundle["certificates"].([]any)
	leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
	// This constructor creates a registered global child. V1 requires every
	// identity ancestor of a registered child to be registered (contract §3);
	// presenting a valid local chain does not promote that parent.
	if strings.HasPrefix(leaf["id"].(string), "did:key:") {
		return nil, fmt.Errorf("%w: a registered child requires a registered identity parent; select a global owner with its installed chain", &awid.IDCertificateError{Code: "unregistered_parent"})
	}
	domain := leaf["domain"].(string)
	_, origin, err := childIssuerRegistry(ctx, idChildOptions{TXTResolver: resolver}, domain)
	if err != nil {
		return nil, err
	}
	issuer, err := currentAgentIssuer(idChildOptions{WorkingDir: workingDir, IdentityHome: owner.home, RegistryURL: origin, TXTResolver: resolver})
	if err != nil {
		return nil, err
	}
	evidence, err := issuer.evidence(ctx, "", "")
	if err != nil {
		return nil, err
	}
	subject := owner.stableID
	if subject == "" {
		subject = owner.did
	}
	verdict := awid.VerifyIDChain(chain.Bundle, awid.IDChainSubject{ID: subject, DIDKey: owner.did}, evidence, domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid || verdict.Kind == nil || *verdict.Kind != "agent" {
		return nil, fmt.Errorf("selected owner cannot issue: %s", verdict.Reason)
	}
	return issuer, nil
}

// finishHostedIDTree uses the shared import before a registry write and a fresh
// shared verification after it. Native registered chains and local children
// take the same verification/install path without publishing another leaf.
func finishHostedIDTree(ctx context.Context, tree *hostedIDTreeRecovery, response awid.IDTreeCreationResponse, material workspaceTeamIdentityMaterial, root string, registry *awid.RegistryClient, resolver awid.TXTResolver) (*awid.IDChainResult, error) {
	if response.IDChain == nil {
		if response.RegistrationRequest != nil {
			return nil, errors.New("registration requested without a chain")
		}
		if tree.Domain != "" && (tree.Parent["kind"] != "namespace" || response.FieldsPresent) {
			return nil, errors.New("identity created with unknown ancestry: server supplied no chain; retain recovery and retry")
		}
		return nil, nil
	}
	if tree.Domain == "" {
		return nil, errors.New("creation returned an unselected parent chain")
	}
	bundle := map[string]any(response.IDChain)
	// Check public proof shape/signatures and the selected operation before
	// discovering its registry. Current issuer authority comes from the SDK.
	if _, err := awid.EncodeIDChainHeader(bundle); err != nil {
		return nil, err
	}
	subjectID := material.StableID
	if material.IdentityScope == awid.IdentityModeLocal {
		subjectID = material.DIDKey
	}
	subject := awid.IDChainSubject{ID: subjectID, DIDKey: material.DIDKey}
	expected := map[string]any{"id": subjectID, "domain": tree.Domain, "parent": tree.Parent, "kind": "agent"}
	certificates := bundle["certificates"].([]any)
	leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
	for _, field := range []string{"id", "domain", "parent", "kind"} {
		if !reflect.DeepEqual(leaf[field], expected[field]) {
			return nil, &awid.IDCertificateError{Code: "request_binding_mismatch"}
		}
	}
	_, origin, err := childIssuerRegistry(ctx, idChildOptions{TXTResolver: resolver}, tree.Domain)
	if err != nil {
		return nil, err
	}
	evidence := idStatusAt(registry, resolver, origin).IDChainEvidence(ctx, bundle, subject, tree.Domain)
	if response.RegistrationRequest != nil {
		if _, err := awid.ImportIDCertificateChain(expected, bundle, evidence, tree.Domain); err != nil {
			return nil, fmt.Errorf("creation chain binding or issuer refused: %w", err)
		}
		if material.IdentityScope != awid.IdentityModeGlobal {
			return nil, errors.New("local child must not request registry registration")
		}
		args := response.RegistrationRequest
		if _, err := registry.RegisterIDCertificateAt(ctx, origin, bundle, awid.KeySigner(material.SigningKey), args.ExpectedHead, args.InvitationID); err != nil {
			return nil, fmt.Errorf("identity registration pending, retain recovery and retry: %w", err)
		}
	}
	// A separate status client cannot reuse the pre-registration snapshot, which
	// may legitimately lack this child for the entire normal cache lifetime.
	fresh := evidence
	if response.RegistrationRequest != nil {
		fresh = idStatusAt(registry, resolver, origin).IDChainEvidence(ctx, bundle, subject, tree.Domain)
	}
	verdict := awid.VerifyIDChain(bundle, subject, fresh, tree.Domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid {
		return nil, fmt.Errorf("identity registration could not be verified: %s; retain recovery and retry", verdict.Reason)
	}
	if err := awconfig.SaveInstalledIDChain(root, bundle); err != nil {
		return nil, err
	}
	return &verdict, nil
}

type apiKeyCreationTeam struct {
	TeamID          string `json:"team_id"`
	CanonicalTeamID string `json:"canonical_team_id"`
	Domain          string `json:"-"`
}

func readAPIKeyCreationTeam(ctx context.Context, baseURL, apiKey string) (*apiKeyCreationTeam, error) {
	base, err := normalizeAPIKeyBootstrapBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/teams/current", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	request.Header.Set("Accept", "application/json")
	response, err := awid.DoServerRequest(&http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}, request, base)
	if err != nil {
		return nil, fmt.Errorf("selected API-key team unavailable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("selected API-key team unavailable (HTTP %d)", response.StatusCode)
	}
	raw, err := awid.ReadAllBounded(response.Body, awid.MaxResponseSize)
	if err != nil {
		return nil, err
	}
	var selected apiKeyCreationTeam
	if err := json.Unmarshal(raw, &selected); err != nil {
		return nil, err
	}
	domain, name, err := awid.ParseTeamID(selected.CanonicalTeamID)
	if err != nil || !hostedIdentityTeamUUID.MatchString(selected.TeamID) || awid.BuildTeamID(domain, name) != selected.CanonicalTeamID {
		return nil, errors.New("selected API-key team has no canonical namespace authority; retry when team metadata is available")
	}
	selected.Domain = domain
	return &selected, nil
}
