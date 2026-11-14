package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// A deployment root's endorsement (identity.root.endorse/default,
// human-assurance-contract.md sections 2 and 5): this identity, a registered
// agent, asks its protected service for the one live act in which a human
// endorses it as the deployment's root, under the service's existing default
// admission policy. The human approves the exact act on the service's page;
// the service signs the root's ID certificate with the human's key, which only
// it holds. aw verifies the certificate, registers it with the root's own
// proof at the pinned registry and reads it back.

var (
	idEndorseHumanFlag     string
	idEndorseTeamsFlag     []string
	idEndorseLabelFlag     string
	idEndorseOperationFlag string
	idEndorseNoWaitFlag    bool
	idEndorseNoBrowserFlag bool
	idEndorseReplaceFlag   string
)

var idEndorseCmd = &cobra.Command{
	Use:   "endorse",
	Short: "Have a human endorse this agent as the deployment's root, through the protected service",
	Long: "Ask the protected service named by --protected-profile to have --human endorse\n" +
		"this registered agent as the deployment's root for --team. The human approves the\n" +
		"exact act on the service's page; nothing is signed here. Before the page is shown,\n" +
		"aw checks the admission policy the service froze against its own read of every\n" +
		"team's policy. Endorsement grants no resource permissions and creates no policy.\n\n" +
		"Without --operation-id, aw keeps a new UUID before anything is sent, and running\n" +
		"the same command again continues that request. With --operation-id, running\n" +
		"again with the same id and inputs resumes that operation; changed inputs refuse\n" +
		"operation_conflict. Once the endorsement commits, aw registers the root's new\n" +
		"certificate at the pinned registry and reads it back.",
	Args: cobra.NoArgs,
	RunE: runIDEndorse,
}

func init() {
	flags := idEndorseCmd.Flags()
	flags.StringVar(&idEndorseHumanFlag, "human", "", "The did:aw of the human who endorses this root")
	flags.StringArrayVar(&idEndorseTeamsFlag, "team", nil, "A team (name:domain) the root will admit agents to; repeat for each")
	flags.StringVar(&idEndorseLabelFlag, "deployment-label", "", "The deployment's name, shown to the human")
	flags.StringVar(&idEndorseOperationFlag, "operation-id", "", "The UUID for this endorsement; by default aw continues the same unfinished request or starts a new one")
	flags.StringVar(&appProtectedProfileFlag, "protected-profile", "", "The operator-provisioned protected-service profile (default: AWEB_PROTECTED_PROFILE, else protected-profile.json in the identity home)")
	flags.BoolVar(&idEndorseNoWaitFlag, "no-wait", false, "Exit without waiting for the approver; run the same command again to finish")
	flags.BoolVar(&idEndorseNoBrowserFlag, "no-browser", false, "Do not open a browser; the page is only reported")
	flags.StringVar(&idEndorseReplaceFlag, "replace", "", "The id of an earlier unfinished endorsement of this root, which stays kept, to ask for a separately approved one")
	identityCmd.AddCommand(idEndorseCmd)
}

// endorsementRequest is one endorsement as the caller names it.
type endorsementRequest struct {
	OperationID     string
	Human           string
	Teams           []string
	DeploymentLabel string
	RootID          string
	RootKey         string
}

// endorsementBinding is the profile's one binding of human's own identity key.
func endorsementBinding(profile *handoff.Profile, human string) (*handoff.ProfileBinding, error) {
	var matches []*handoff.ProfileBinding
	for i := range profile.Bindings {
		authority, _ := profile.Bindings[i].Scope["authority"].(map[string]any)
		holder, _ := profile.Bindings[i].Scope["human"].(map[string]any)
		if authority["kind"] == "human_identity" && authority["id"] == human && holder["id"] == human {
			matches = append(matches, &profile.Bindings[i])
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, withErrorCode("profile_scope_refused", fmt.Errorf("the protected-service profile configures no identity key for %s", human))
	}
	return nil, withErrorCode("profile_scope_ambiguous", fmt.Errorf("the protected-service profile binds %s's identity key %d times; it must name one", human, len(matches)))
}

// endorsementIntent is the act aw asks the service to prepare: the root in the
// human's domain, its distinct canonical teams in code-point order.
func endorsementIntent(profile *handoff.Profile, binding *handoff.ProfileBinding, request endorsementRequest) (map[string]any, error) {
	if strings.TrimSpace(request.DeploymentLabel) == "" {
		return nil, usageError("--deployment-label is required: the deployment's name the human sees")
	}
	teams := slices.Clone(request.Teams)
	slices.Sort(teams)
	if len(teams) == 0 || len(slices.Compact(slices.Clone(teams))) != len(teams) {
		return nil, usageError("--team must name each team once, at least one")
	}
	listed := make([]any, len(teams))
	for i, team := range teams {
		if domain, name, err := awid.ParseTeamID(team); err != nil || name+":"+domain != team {
			return nil, usageError("--team %q is not a canonical team (name:domain, lowercase)", team)
		}
		listed[i] = team
	}
	authority, _ := binding.Scope["authority"].(map[string]any)
	return map[string]any{
		"operation": "identity.root.endorse", "variant": "default", "approval_format": "intent_v1",
		"scope": binding.Scope, "audience": profile.RegistryOrigin,
		"subject": map[string]any{"domain": authority["domain"], "root_id": request.RootID, "root_key": request.RootKey,
			"teams": listed, "deployment_label": request.DeploymentLabel},
	}, nil
}

// savedEndorsement is the saved prepare body under operationID when it holds
// exactly intent, nil when nothing is saved, and operation_conflict otherwise.
// The saved bytes carry the original callback, which a resume never replaces.
func savedEndorsement(profile *handoff.Profile, operationID string, intent map[string]any) ([]byte, error) {
	saved, err := awconfig.LoadPendingGovernanceOperation(operationID)
	if err != nil || saved == nil {
		return nil, err
	}
	if saved.Quarantine != nil {
		return nil, quarantinedOperation(operationID)
	}
	conflict := withErrorCode("operation_conflict", fmt.Errorf("operation %s was requested with other inputs or at another service; a changed endorsement needs a new operation id", operationID))
	body, ok := handoff.DecodeObject(saved.Body)
	if !ok || saved.RequestOrigin != profile.RequestOrigin || saved.HumanOrigin != profile.HumanOrigin || body["operation_id"] != operationID {
		return nil, conflict
	}
	delete(body, "operation_id")
	delete(body, "redirect_uri")
	savedIntent, errSaved := awid.StrictCanonicalJSON(body)
	asked, errAsked := json.Marshal(intent)
	askedBody, okAsked := handoff.DecodeObject(asked)
	askedIntent, errCanonical := awid.StrictCanonicalJSON(askedBody)
	if errSaved != nil || errAsked != nil || !okAsked || errCanonical != nil || !bytes.Equal(savedIntent, askedIntent) {
		return nil, conflict
	}
	return saved.Body, nil
}

// endorsementCheck checks a prepared endorsement before its page is shown: the
// human's pinned key issues it, and for every team aw's own policy read, under
// the caller's context, is a protected team whose policy is exactly the frozen
// one. A read that ends or fails is never taken as a policy. It keeps the
// frozen request it accepted in kept.
func endorsementCheck(issuerKey string, teams []string, readPolicy func(context.Context, string) (*handoff.AdmissionPolicyRead, error), kept *map[string]any) func(context.Context, map[string]any) error {
	return func(ctx context.Context, request map[string]any) error {
		template, err := handoff.IntentTemplate(request)
		if err != nil {
			return err
		}
		if template["issuer_key"] != issuerKey {
			return withErrorCode("operation_mismatch", errors.New("the prepared certificate is issued by another key than the profile pins for the human"))
		}
		frozen, err := awid.StrictCanonicalJSON(request["admission_policy"])
		if err != nil {
			return withErrorCode("operation_mismatch", errors.New("the prepared admission policy is not canonical"))
		}
		for _, team := range teams {
			read, err := readPolicy(ctx, team)
			if err != nil {
				return err
			}
			policy, err := read.RequireAdmissionPolicy()
			if err != nil || policy == nil {
				return withErrorCode("admission_policy_missing", fmt.Errorf("team %s has no protected admission policy at this service", team))
			}
			current, err := awid.StrictCanonicalJSON(policy.Fields)
			if err != nil || !bytes.Equal(current, frozen) {
				return withErrorCode("policy_changed", fmt.Errorf("team %s's admission policy is not the policy the endorsement froze; nothing is shown for approval", team))
			}
		}
		*kept = request
		return nil
	}
}

// pendingEndorsementReport is what a caller that does not wait shows the
// human: the page to approve on and what it must show, until when.
func pendingEndorsementReport(prepared *handoff.Prepared, page string, receipt *handoff.Receipt) map[string]any {
	return map[string]any{
		"operation_id": prepared.OperationID, "state": receipt.State, "reason": receipt.Reason, "page": page,
		"digest": prepared.Digest, "fingerprint": handoff.Fingerprint(prepared.Digest),
		"expires_at": prepared.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
}

// pendingEndorsementText says, for people, who decides an endorsement that was
// not waited for, the page they approve on and how to continue; --json keeps
// the digest. It claims no notice, which the prepare answer cannot show.
func pendingEndorsementText(report map[string]any) string {
	expires, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(report["expires_at"]))
	return fmt.Sprintf("Waiting for the approver, who approves on %s; the request expires at %s. Run the same command again to continue (operation %s).\n",
		report["page"], handoff.ReaderTime(expires, "2006-01-02 15:04"), report["operation_id"])
}

// endorsedCertificate is the root's signed ID certificate in a committed
// result, in the standard {certificate, signature} wrapper, if it is the
// certificate issued under the human's approval of frozen: the intent's
// template in every static field, issued_at inside the frozen issuance
// window, signed by the human's pinned key. Anything else, including no
// frozen intent, is signed_certificate_invalid.
func endorsedCertificate(result []byte, frozen map[string]any, issuerKey string) (map[string]any, error) {
	invalid := func(format string, args ...any) error {
		return withErrorCode("signed_certificate_invalid", fmt.Errorf("the signed certificate is not the one the human approved: "+format, args...))
	}
	fields, ok := handoff.DecodeObject(result)
	signingText, _ := fields["signing"].(string)
	signatureText, _ := fields["signature"].(string)
	if !ok || len(fields) != 2 || signingText == "" || signatureText == "" || strings.ContainsAny(signingText+signatureText, "\r\n") {
		return nil, invalid("the result is not exactly a signing and a signature")
	}
	signing, errSigning := base64.StdEncoding.Strict().DecodeString(signingText)
	signature, errSignature := base64.StdEncoding.Strict().DecodeString(signatureText)
	if errSigning != nil || errSignature != nil || len(signature) != ed25519.SignatureSize {
		return nil, invalid("its signing or signature is not padded base64 of the right size")
	}
	// The signature is verified over the issued certificate's own canonical
	// bytes, so signing bytes that are anything else never verify.
	issued, _ := handoff.DecodeObject(bytes.TrimPrefix(signing, []byte(awid.IDCertificatePrefix)))
	if err := handoff.VerifyIssuedArtifact(frozen, issued); err != nil {
		return nil, invalid("it is not the certificate the operation froze: %v", err)
	}
	signed := map[string]any{"certificate": issued, "signature": base64.RawURLEncoding.EncodeToString(signature)}
	if err := awid.VerifyIDCertificate(signed, issuerKey); err != nil {
		return nil, invalid("%v", err)
	}
	return signed, nil
}

// rootRegistry is where an endorsed root registers its certificate.
type rootRegistry interface {
	register(ctx context.Context, bundle map[string]any, expectedHead *string) error
	// currentHead answers the root's current certificate ID at the registry,
	// having verified bundle as the root's whole chain when that ID is
	// bundle's own leaf.
	currentHead(ctx context.Context, bundle map[string]any) (string, error)
}

// registerEndorsement registers signed with its supporting chain, confirms it
// by reading the root's current certificate back, and installs that confirmed
// chain in home so the root can issue children. A registration whose answer
// failed is confirmed by that read-back too; another current head is a
// conflict, and no read-back leaves it unconfirmed; neither installs anything.
// Installing again writes the same chain.
func registerEndorsement(ctx context.Context, registry rootRegistry, chain []any, signed map[string]any, expectedHead *string, home string) error {
	bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": append(slices.Clone(chain), signed)}
	ours, err := awid.IDCertificateID(signed["certificate"].(map[string]any))
	if err != nil {
		return err
	}
	registerErr := registry.register(ctx, bundle, expectedHead)
	current, err := registry.currentHead(ctx, bundle)
	switch {
	case err != nil:
		return withErrorCode("registration_unconfirmed", fmt.Errorf("the endorsed certificate %s could not be read back (%v; registration: %v); run again with the same operation id", ours, err, registerErr))
	case current != ours:
		return withErrorCode("registration_conflict", fmt.Errorf("the registry's current certificate for the root is %s, not the endorsed %s (registration: %v)", current, ours, registerErr))
	}
	if err := awconfig.SaveInstalledIDChain(home, bundle); err != nil {
		return fmt.Errorf("the endorsed certificate %s is registered, but its chain could not be installed in %s: %w; run again with the same operation id", ours, home, err)
	}
	return nil
}

// pinnedStatusClient reads identity-tree status from the profile's registry,
// trusting the namespace controller keys the profile pins, never DNS.
func pinnedStatusClient(registry *awid.RegistryClient, profile *handoff.Profile) *awid.IDStatusClient {
	status := awid.NewIDStatusClient(registry, nil)
	status.Route = func(context.Context, string) (string, error) { return profile.RegistryOrigin, nil }
	status.Authority = func(_ context.Context, domain string) (awid.DomainAuthority, error) {
		controller := profile.NamespaceAuthorities[domain]
		if controller == "" {
			return awid.DomainAuthority{}, fmt.Errorf("the protected-service profile pins no namespace authority for %s", domain)
		}
		return awid.DomainAuthority{ControllerDID: controller, RegistryURL: profile.RegistryOrigin, DNSName: awid.AWIDTXTName(domain)}, nil
	}
	return status
}

// humanSupportingChain is human's registered chain, verified against the
// pinned registry's status and namespace authority: the chain the root's new
// certificate is registered on.
func humanSupportingChain(ctx context.Context, status *awid.IDStatusClient, human, humanKey, domain string) ([]any, error) {
	subject := awid.IDChainSubject{ID: human, DIDKey: humanKey}
	evidence := status.IDChainEvidence(ctx, nil, subject, domain)
	bundle, err := awid.RegisteredIDChain(evidence.Status, human)
	if err != nil {
		return nil, fmt.Errorf("the registered chain of %s: %w", human, err)
	}
	result := awid.VerifyIDChain(bundle, subject, evidence, domain)
	if result.Reason != "verified" || result.HumanID == nil || *result.HumanID != human {
		return nil, withErrorCode("human_chain_unverified", fmt.Errorf("the registered chain of %s does not verify (%s)", human, result.Reason))
	}
	return bundle["certificates"].([]any), nil
}

// pinnedRootRegistry registers at the profile's registry with the root's own
// key and reads the root back through pinned status.
type pinnedRootRegistry struct {
	registry *awid.RegistryClient
	profile  *handoff.Profile
	root     awid.IDChainSubject
	domain   string
	signer   awid.IDCertificateSigner
}

func (r *pinnedRootRegistry) register(ctx context.Context, bundle map[string]any, expectedHead *string) error {
	_, err := r.registry.RegisterIDCertificateAt(ctx, r.profile.RegistryOrigin, bundle, r.signer, expectedHead, nil)
	return err
}

func (r *pinnedRootRegistry) currentHead(ctx context.Context, bundle map[string]any) (string, error) {
	// A fresh client: the read-back never answers from evidence read before
	// the registration.
	evidence := pinnedStatusClient(r.registry, r.profile).IDChainEvidence(ctx, bundle, r.root, r.domain)
	current, err := awid.RegisteredIDHead(evidence, r.domain, r.root.ID)
	if err != nil {
		return "", fmt.Errorf("the registry's status for %s does not verify: %w", r.root.ID, err)
	}
	// Another head, from status that verifies, is the registry's answer;
	// the endorsed head must also verify as the root's whole chain.
	certificates, _ := bundle["certificates"].([]any)
	leaf, _ := certificates[len(certificates)-1].(map[string]any)
	ours, err := awid.IDCertificateID(leaf["certificate"].(map[string]any))
	if err != nil || current != ours {
		return current, nil
	}
	if result := awid.VerifyIDChain(bundle, r.root, evidence, r.domain); result.Reason != "verified" {
		return "", fmt.Errorf("the root's chain does not verify at the registry (%s)", result.Reason)
	}
	return current, nil
}

func runIDEndorse(cmd *cobra.Command, _ []string) error {
	request := endorsementRequest{OperationID: strings.TrimSpace(idEndorseOperationFlag), Human: strings.TrimSpace(idEndorseHumanFlag),
		Teams: idEndorseTeamsFlag, DeploymentLabel: strings.TrimSpace(idEndorseLabelFlag)}
	if request.Human == "" {
		return usageError("--human is required: the did:aw of the human who endorses this root")
	}
	profile, err := loadProtectedProfile()
	if err != nil {
		return err
	}
	binding, err := endorsementBinding(profile, request.Human)
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	if identity.StableID == "" {
		return usageError("only a registered agent (with a did:aw) can be endorsed as a root")
	}
	request.RootID, request.RootKey = identity.StableID, identity.DIDKey
	intent, err := endorsementIntent(profile, binding, request)
	if err != nil {
		return err
	}
	// An earlier endorsement aw cannot continue is read and settled, or
	// explicitly replaced, before a new one is asked for; its result can
	// only be kept, never registered by this aw (endorsementReading).
	if _, err := guardUnfinished(cmd.Context(), cmd.ErrOrStderr(), profile, requesterOptions(cmd, profile, identity), intent, sameCanonical,
		strings.TrimSpace(idEndorseReplaceFlag), endorsementReading); err != nil {
		return err
	}
	if err := announceOperationID(cmd, &request.OperationID, profile, intent); err != nil {
		return err
	}
	saved, err := savedEndorsement(profile, request.OperationID, intent)
	if err != nil {
		return err
	}
	teams := slices.Sorted(slices.Values(request.Teams))
	readPolicy := func(ctx context.Context, team string) (*handoff.AdmissionPolicyRead, error) {
		opts := handoff.GovernanceOptions{Request: profile.RequestOrigin, Sign: protectedRequesterSigner(profile, admissionPolicyScope(profile, team), identity)}
		return handoff.ReadAdmissionPolicy(ctx, opts, profile.ServiceID, team)
	}
	var frozen map[string]any
	opts := governanceOptions(cmd, profile, binding.Scope, identity)
	opts.CheckPrepared = endorsementCheck(binding.AuthorityKeyDID, teams, readPolicy, &frozen)
	if idEndorseNoBrowserFlag {
		opts.Open = nil
	}
	var presented *handoff.Prepared
	var page string
	opts.NoWait = idEndorseNoWaitFlag
	opts.OnPresented = func(prepared *handoff.Prepared, shown string) { presented, page = prepared, shown }
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	fmt.Fprintf(cmd.ErrOrStderr(), "Endorsement of %s as the root for %s, approved by %s through %s\n", request.RootID, strings.Join(teams, ", "), request.Human, profile.ServiceID)
	var receipt *handoff.Receipt
	if saved != nil {
		receipt, err = handoff.Resume(ctx, opts, saved)
	} else {
		receipt, err = handoff.Approve(ctx, opts, request.OperationID, intent)
	}
	if receipt != nil && receipt.State == "refused" {
		forgetProtectedOperationQuietly(request.OperationID)
	}
	if err != nil {
		if code := handoff.ErrorCode(err); code != "" {
			return withErrorCode(code, fmt.Errorf("%w (operation %s)", err, request.OperationID))
		}
		return fmt.Errorf("operation %s: %w", request.OperationID, err)
	}
	if receipt.State == "pending" && presented != nil {
		// Not waited for: the signer has emailed the approver, and running
		// the same command again finds this operation and finishes it.
		report := pendingEndorsementReport(presented, page, receipt)
		printOutput(report, func(any) string { return pendingEndorsementText(report) })
		return nil
	}
	signed, err := endorsedCertificate(receipt.Result, frozen, binding.AuthorityKeyDID)
	if err != nil {
		return fmt.Errorf("operation %s: %w", request.OperationID, err)
	}
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	if err := registry.TrustRegistryOrigin(profile.RegistryOrigin); err != nil {
		return err
	}
	domain, _ := binding.Scope["authority"].(map[string]any)["domain"].(string)
	chain, err := humanSupportingChain(ctx, pinnedStatusClient(registry, profile), request.Human, binding.AuthorityKeyDID, domain)
	if err != nil {
		return fmt.Errorf("operation %s committed; %w", request.OperationID, err)
	}
	var expectedHead *string
	if head, ok := frozen["expected_head"].(string); ok {
		expectedHead = &head
	}
	root := &pinnedRootRegistry{registry: registry, profile: profile, domain: domain, signer: awid.KeySigner(identity.SigningKey),
		root: awid.IDChainSubject{ID: request.RootID, DIDKey: request.RootKey}}
	if err := registerEndorsement(ctx, root, chain, signed, expectedHead, filepath.Dir(identity.SigningKeyPath)); err != nil {
		return fmt.Errorf("operation %s committed; %w", request.OperationID, err)
	}
	certificateID, _ := awid.IDCertificateID(signed["certificate"].(map[string]any))
	forgetProtectedOperationQuietly(request.OperationID)
	report := map[string]any{"operation_id": request.OperationID, "state": receipt.State, "certificate_id": certificateID, "registered": true, "chain_installed": true}
	printOutput(report, func(any) string {
		return fmt.Sprintf("Operation %s committed; %s is endorsed by %s and registered as certificate %s.\n", request.OperationID, request.RootID, request.Human, certificateID)
	})
	return nil
}

// endorsementReading keeps an unfinished endorsement's committed receipt with
// the signed bytes it carries: aw no longer holds the certificate that
// request froze, so it can neither verify nor register it.
func endorsementReading(_ *awconfig.PendingGovernanceOperation, _ map[string]any, result []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
	facts := &awconfig.GovernanceQuarantine{State: "committed", Verification: "unverifiable"}
	if signing, signature, reason := signedResult(result); reason == "" {
		facts.Signing, facts.Signature = signing, signature
	}
	return nil, facts
}
