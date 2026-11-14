package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// An agent membership's bounded removal (team.agent.remove/default,
// docs/protected-team-removal.md): the deployment's endorsed root asks the
// protected service to revoke one agent certificate it admitted. The service
// signs the registry's revoke request with the controller key only it holds,
// revokes, and confirms; aw checks that what was signed is exactly that
// revocation under the profile's pinned key. aw holds no controller key.

var (
	teamRemoveAgentCertificateFlag string
	teamRemoveAgentOperationIDFlag string
)

var teamRemoveAgentCmd = &cobra.Command{
	Use:   "remove-agent",
	Short: "Remove an admitted agent from a protected team through its protected service, as the endorsed root",
	Long: "Remove one agent's membership of a protected team, through the protected service\n" +
		"named by --protected-profile, proving this identity's key as the deployment's\n" +
		"endorsed root that admitted it. The membership is the one --certificate names:\n" +
		"the certificate file aw id team admit wrote, or the agent home's installed copy.\n" +
		"No human approves it, and nothing in the agent's home is changed.\n\n" +
		"Without --operation-id, aw keeps a new UUID before anything is sent, and running\n" +
		"the same command again continues that request. With --operation-id, running\n" +
		"again with the same id and the same inputs resumes that operation and returns its\n" +
		"receipt; changed inputs under the id refuse operation_conflict.",
	Args: cobra.NoArgs,
	RunE: runTeamRemoveAgent,
}

func init() {
	flags := teamRemoveAgentCmd.Flags()
	flags.StringVar(&teamRemoveAgentCertificateFlag, "certificate", "", "The agent's team certificate file")
	flags.StringVar(&teamRemoveAgentOperationIDFlag, "operation-id", "", "The UUID for this removal; by default aw continues the same unfinished request or starts a new one")
	flags.StringVar(&appProtectedProfileFlag, "protected-profile", "", "The operator-provisioned protected-service profile (default: AWEB_PROTECTED_PROFILE, else protected-profile.json in the identity home)")
	teamCmd.AddCommand(teamRemoveAgentCmd)
}

// removalRequest is one removal as the caller names it: the certificate file
// whose membership the root RootID, proving RootKey, removes.
type removalRequest struct {
	OperationID string
	Certificate string
	RootID      string
	RootKey     string
}

// removalBody is the exact prepare body removing cert's membership under
// binding. The membership snapshot keeps absent fields as explicit nulls.
func removalBody(profile *handoff.Profile, binding *handoff.ProfileBinding, request removalRequest, cert *awid.TeamCertificate) map[string]any {
	subject := membershipSubject(cert)
	subject["root_id_or_self"] = request.RootID
	return map[string]any{
		"operation_id": request.OperationID, "operation": "team.agent.remove", "variant": "default",
		"scope": binding.Scope, "audience": profile.RegistryOrigin, "subject": subject,
	}
}

// removeMember runs request's removal and returns its receipt.
func removeMember(ctx context.Context, opts handoff.GovernanceOptions, profile *handoff.Profile, request removalRequest) (map[string]any, error) {
	cert, err := awid.LoadTeamCertificate(request.Certificate)
	if err != nil {
		return nil, withErrorCode("certificate_invalid", fmt.Errorf("%s is not a team certificate: %w", request.Certificate, err))
	}
	binding, err := admissionBinding(profile, cert.Team)
	if err != nil {
		return nil, err
	}
	raw, err := operationBytes(profile, request.OperationID, removalBody(profile, binding, request, cert))
	if err != nil {
		return nil, err
	}
	opts.CheckPrepared = func(_ context.Context, frozen map[string]any) error {
		artifact, _ := frozen["artifact"].(map[string]any)
		if artifact["controller_did"] != binding.AuthorityKeyDID {
			return withErrorCode("operation_mismatch", errors.New("the prepared revocation names another controller than the profile pins"))
		}
		if frozen["requester_key"] != request.RootKey {
			return withErrorCode("operation_mismatch", errors.New("the prepared revocation names another requester key than this root's"))
		}
		return nil
	}
	receipt, prepared, err := handoff.Execute(ctx, opts, raw)
	if receipt != nil && receipt.State == "refused" {
		forgetProtectedOperationQuietly(request.OperationID)
	}
	if err != nil {
		if code := handoff.ErrorCode(err); code != "" {
			return nil, withErrorCode(code, fmt.Errorf("%w (operation %s)", err, request.OperationID))
		}
		return nil, fmt.Errorf("operation %s: %w", request.OperationID, err)
	}
	if err := signedRevocation(receipt.Result, prepared, binding.AuthorityKeyDID); err != nil {
		return nil, fmt.Errorf("operation %s: %w", request.OperationID, err)
	}
	forgetProtectedOperationQuietly(request.OperationID)
	return map[string]any{"operation_id": request.OperationID, "state": receipt.State, "certificate_id": cert.CertificateID}, nil
}

// signedRevocation accepts a committed removal's result only as the
// controller's signature over exactly the registry request the verified
// operation froze. Anything else is signed_request_invalid.
func signedRevocation(result []byte, prepared *handoff.Prepared, controllerDID string) error {
	invalid := func(format string, args ...any) error {
		return withErrorCode("signed_request_invalid", fmt.Errorf("the signed revocation is not the one aw requested: "+format, args...))
	}
	if prepared == nil {
		if _, _, reason := signedResult(result); reason != "" {
			return invalid("%s", reason)
		}
		return invalid("its prepared operation was never verified")
	}
	payload, _ := handoff.DecodeObject(prepared.Payload)
	request, _ := payload["request"].(map[string]any)
	return signedFrozenRevocation(result, request, controllerDID)
}

// signedFrozenRevocation accepts a committed removal's result only as the
// controller's signature over exactly the registry request in request, the
// verified operation's frozen request. Anything else is
// signed_request_invalid.
func signedFrozenRevocation(result []byte, request map[string]any, controllerDID string) error {
	invalid := func(format string, args ...any) error {
		return withErrorCode("signed_request_invalid", fmt.Errorf("the signed revocation is not the one aw requested: "+format, args...))
	}
	signing, signature, reason := signedResult(result)
	if reason != "" {
		return invalid("%s", reason)
	}
	artifact, _ := request["artifact"].(map[string]any)
	frozen, err := awid.StrictCanonicalJSON(artifact["request"])
	if err != nil || !bytes.Equal(frozen, signing) {
		return invalid("it is not the registry request the operation froze")
	}
	if err := awid.VerifyControllerRequestSignature(controllerDID, signature, signing); err != nil {
		return invalid("it is not signed by the pinned controller: %v", err)
	}
	return nil
}

func runTeamRemoveAgent(cmd *cobra.Command, _ []string) error {
	request := removalRequest{
		OperationID: strings.TrimSpace(teamRemoveAgentOperationIDFlag), Certificate: strings.TrimSpace(teamRemoveAgentCertificateFlag),
	}
	if request.Certificate == "" {
		return usageError("--certificate is required")
	}
	profile, err := loadProtectedProfile()
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	if identity.StableID == "" {
		return usageError("only a registered root (with a did:aw) can request a removal")
	}
	request.RootID, request.RootKey = identity.StableID, identity.DIDKey
	cert, err := awid.LoadTeamCertificate(request.Certificate)
	if err != nil {
		return withErrorCode("certificate_invalid", fmt.Errorf("%s is not a team certificate: %w", request.Certificate, err))
	}
	binding, err := admissionBinding(profile, cert.Team)
	if err != nil {
		return err
	}
	if err := announceOperationID(cmd, &request.OperationID, profile, removalBody(profile, binding, request, cert)); err != nil {
		return err
	}
	opts := handoff.GovernanceOptions{
		Request: profile.RequestOrigin, Human: profile.HumanOrigin,
		Sign: protectedRequesterSigner(profile, binding.Scope, identity), Notify: cmd.ErrOrStderr(),
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Removing %s from %s through %s, operation %s\n", cert.Alias, cert.Team, profile.ServiceID, request.OperationID)
	report, err := removeMember(cmd.Context(), opts, profile, request)
	if err != nil {
		return err
	}
	printOutput(report, func(any) string {
		return fmt.Sprintf("Operation %s committed; %s's membership of %s (certificate %s) is removed\n", request.OperationID, cert.Alias, cert.Team, cert.CertificateID)
	})
	return nil
}
