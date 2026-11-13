package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// An agent's bounded team admission (team.agent.admit/default,
// human-assurance-contract.md sections 2 and 5): this identity, the
// deployment's endorsed root, asks the protected service to admit one agent
// under the team's admission policy, with no human present. The service signs
// the agent's membership certificate with the controller key only it holds;
// aw verifies it under the profile's pinned key and writes it where the caller
// says. aw holds no controller key.

var (
	teamAdmitTeamFlag           string
	teamAdmitMemberKeyFlag      string
	teamAdmitMemberIDFlag       string
	teamAdmitAliasFlag          string
	teamAdmitPolicyVersionFlag  int64
	teamAdmitPolicyDigestFlag   string
	teamAdmitOperationIDFlag    string
	teamAdmitCertificateOutFlag string
)

var teamAdmitCmd = &cobra.Command{
	Use:   "admit",
	Short: "Admit an agent to a protected team through its protected service, as the endorsed root",
	Long: "Admit one agent to a protected team as an ordinary member, through the protected\n" +
		"service named by --protected-profile, proving this identity's key as the\n" +
		"deployment's endorsed root. No human approves it: the service admits only within\n" +
		"the team's admission policy, whose version and digest the caller names as read\n" +
		"from aw id team admission-policy.\n\n" +
		"Without --operation-id, aw keeps a new UUID before anything is sent, and running\n" +
		"the same command again continues that request. With --operation-id, running\n" +
		"again with the same id and the same inputs resumes that operation and returns its\n" +
		"original certificate; changed inputs under the id refuse operation_conflict. The\n" +
		"verified membership certificate is written to --certificate-out.",
	Args: cobra.NoArgs,
	RunE: runTeamAdmit,
}

func init() {
	flags := teamAdmitCmd.Flags()
	flags.StringVar(&teamAdmitTeamFlag, "team", "", "The protected team (name:domain)")
	flags.StringVar(&teamAdmitMemberKeyFlag, "member-key", "", "The agent's did:key")
	flags.StringVar(&teamAdmitMemberIDFlag, "member-id", "", "The agent's did:aw, when it is a registered identity; omit for a local agent")
	flags.StringVar(&teamAdmitAliasFlag, "alias", "", "The agent's member alias")
	flags.Int64Var(&teamAdmitPolicyVersionFlag, "policy-version", 0, "The admission policy version the caller read")
	flags.StringVar(&teamAdmitPolicyDigestFlag, "policy-digest", "", "The admission policy digest the caller read (sha256:<hex>)")
	flags.StringVar(&teamAdmitOperationIDFlag, "operation-id", "", "The UUID for this admission; by default aw continues the same unfinished request or starts a new one")
	flags.StringVar(&teamAdmitCertificateOutFlag, "certificate-out", "", "Where to write the agent's membership certificate")
	flags.StringVar(&appProtectedProfileFlag, "protected-profile", "", "The operator-provisioned protected-service profile (default: AWEB_PROTECTED_PROFILE, else protected-profile.json in the identity home)")
	teamCmd.AddCommand(teamAdmitCmd)
}

// admissionRequest is one admission as the caller names it.
type admissionRequest struct {
	OperationID    string
	Team           string
	RootID         string
	RootKey        string
	ChildID        string
	ChildKey       string
	Alias          string
	PolicyVersion  int64
	PolicyDigest   string
	CertificateOut string
	// Counts reads the root's own admissions, to tell a limit refusal with
	// numbers; nil reads none.
	Counts func(context.Context) (*handoff.AdmissionCounts, error)
}

var operationIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validOperationID refuses anything but a lowercase UUID, the form aw keeps
// an operation's request under.
func validOperationID(id string) error {
	if !operationIDPattern.MatchString(id) {
		return usageError("--operation-id must be a lowercase UUID")
	}
	return nil
}

// admissionBinding is the profile's one binding for team's controller.
func admissionBinding(profile *handoff.Profile, team string) (*handoff.ProfileBinding, error) {
	var matches []*handoff.ProfileBinding
	for i := range profile.Bindings {
		authority, _ := profile.Bindings[i].Scope["authority"].(map[string]any)
		if authority["kind"] == "team_controller" && authority["id"] == team {
			matches = append(matches, &profile.Bindings[i])
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, withErrorCode("profile_scope_refused", fmt.Errorf("the protected-service profile configures no controller binding for team %s", team))
	}
	return nil, withErrorCode("profile_scope_ambiguous", fmt.Errorf("the protected-service profile binds team %s's controller %d times; it must name one", team, len(matches)))
}

// admissionBody is the exact prepare body of request under binding.
func admissionBody(profile *handoff.Profile, binding *handoff.ProfileBinding, request admissionRequest) map[string]any {
	var childID any
	if request.ChildID != "" {
		childID = request.ChildID
	}
	return map[string]any{
		"operation_id": request.OperationID, "operation": "team.agent.admit", "variant": "default",
		"scope": binding.Scope, "audience": profile.RegistryOrigin,
		"subject": map[string]any{
			"team_id": request.Team, "root_id": request.RootID, "root_key": request.RootKey,
			"child_id": childID, "child_key": request.ChildKey, "member_alias": request.Alias,
			"admission_policy_digest": request.PolicyDigest, "expected_policy_version": request.PolicyVersion,
		},
	}
}

// operationBytes is the body to send under a protected operation's id: the
// saved bytes when that id already holds exactly this body, or body saved
// now, before anything is sent. Another body under the id is
// operation_conflict.
func operationBytes(profile *handoff.Profile, operationID string, body map[string]any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	saved, err := awconfig.LoadPendingGovernanceOperation(operationID)
	if err != nil {
		return nil, err
	}
	if saved == nil {
		return raw, awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{
			OperationID: operationID, RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw,
		})
	}
	same := saved.RequestOrigin == profile.RequestOrigin && saved.HumanOrigin == profile.HumanOrigin
	if same {
		savedBody, okSaved := handoff.DecodeObject(saved.Body)
		newBody, okNew := handoff.DecodeObject(raw)
		savedCanonical, errSaved := awid.StrictCanonicalJSON(savedBody)
		newCanonical, errNew := awid.StrictCanonicalJSON(newBody)
		same = okSaved && okNew && errSaved == nil && errNew == nil && bytes.Equal(savedCanonical, newCanonical)
	}
	if !same {
		return nil, withErrorCode("operation_conflict", fmt.Errorf("operation %s was requested with other inputs or at another service; changed inputs need a new operation id", operationID))
	}
	return saved.Body, nil
}

// admitMember runs request's admission and writes its verified certificate.
func admitMember(ctx context.Context, opts handoff.GovernanceOptions, profile *handoff.Profile, request admissionRequest) (map[string]any, error) {
	binding, err := admissionBinding(profile, request.Team)
	if err != nil {
		return nil, err
	}
	body := admissionBody(profile, binding, request)
	raw, err := operationBytes(profile, request.OperationID, body)
	if err != nil {
		return nil, err
	}
	pinnedKey := func(_ context.Context, frozen map[string]any) error {
		artifact, _ := frozen["artifact"].(map[string]any)
		if artifact["team_did_key"] != binding.AuthorityKeyDID {
			return withErrorCode("operation_mismatch", errors.New("the prepared certificate names another team key than the profile pins"))
		}
		return nil
	}
	opts.CheckPrepared = pinnedKey
	receipt, prepared, err := handoff.Execute(ctx, opts, raw)
	if receipt != nil && receipt.State == "refused" {
		forgetProtectedOperationQuietly(request.OperationID)
	}
	if err != nil {
		err = withAdmissionCounts(ctx, err, request.Team, request.Counts)
		if code := handoff.ErrorCode(err); code != "" {
			return nil, withErrorCode(code, fmt.Errorf("%w (operation %s)", err, request.OperationID))
		}
		return nil, fmt.Errorf("operation %s: %w", request.OperationID, err)
	}
	cert, err := admittedCertificate(receipt.Result, prepared, body, binding.AuthorityKeyDID)
	if err != nil {
		return nil, fmt.Errorf("operation %s: %w", request.OperationID, err)
	}
	if err := writeCertificateOnce(request.CertificateOut, cert); err != nil {
		return nil, fmt.Errorf("operation %s committed; %w", request.OperationID, err)
	}
	forgetProtectedOperationQuietly(request.OperationID)
	return map[string]any{"operation_id": request.OperationID, "state": receipt.State, "certificate_out": request.CertificateOut}, nil
}

// forgetProtectedOperationQuietly drops a settled operation's saved request.
// A failure to forget leaves a stale request behind that a rerun resumes; it
// does not change the outcome.
func forgetProtectedOperationQuietly(operationID string) {
	_ = awconfig.RemovePendingGovernanceOperation(operationID)
}

// admittedCertificate is the membership certificate in a committed result,
// if it is signed by teamKeyDID, is exactly the certificate prepared, the
// verified operation, froze, and names exactly the member body asked for. Anything else is
// signed_certificate_invalid and is not written.
func admittedCertificate(result []byte, prepared *handoff.Prepared, body map[string]any, teamKeyDID string) (*awid.TeamCertificate, error) {
	invalid := func(format string, args ...any) error {
		return withErrorCode("signed_certificate_invalid", fmt.Errorf("the signed certificate is not the one aw requested: "+format, args...))
	}
	signing, signature, reason := retainedSignedResult(result, prepared)
	if reason != "" {
		return nil, invalid("%s", reason)
	}
	signed, ok := handoff.DecodeObject(signing)
	canonical, err := awid.StrictCanonicalJSON(signed)
	if !ok || err != nil || !bytes.Equal(canonical, signing) {
		return nil, invalid("its signing bytes are not a canonical certificate")
	}
	if prepared == nil {
		return nil, invalid("its prepared operation was never verified")
	}
	payload, _ := handoff.DecodeObject(prepared.Payload)
	request, _ := payload["request"].(map[string]any)
	frozen, err := awid.StrictCanonicalJSON(request["artifact"])
	if err != nil || !bytes.Equal(frozen, signing) {
		return nil, invalid("it is not the certificate the operation froze")
	}
	var cert awid.TeamCertificate
	if err := json.Unmarshal(signing, &cert); err != nil {
		return nil, invalid("it is not a team certificate")
	}
	// The check verifies the signature by the pinned team key over the
	// certificate's canonical bytes, which are exactly signing.
	cert.Signature = base64.RawStdEncoding.EncodeToString(signature)
	if err := awid.CheckDecodedTeamCertificate(&cert, teamKeyDID); err != nil {
		return nil, invalid("%v", err)
	}
	subject, _ := body["subject"].(map[string]any)
	childID, _ := subject["child_id"].(string)
	scope := awid.IdentityModeLocal
	if childID != "" {
		scope = awid.IdentityModeGlobal
	}
	if cert.Version != 1 || cert.Team != subject["team_id"] || cert.TeamDIDKey != teamKeyDID || cert.MemberDIDKey != subject["child_key"] ||
		cert.MemberDIDAW != childID || cert.MemberAddress != "" || cert.Alias != subject["member_alias"] || cert.IdentityScope != scope {
		return nil, invalid("it names another team, member, alias or scope")
	}
	return &cert, nil
}

// signedResult is a committed result's signing and signature: exactly those
// two members, each padded standard base64, the signature of Ed25519 size.
// Otherwise it names what is wrong.
func signedResult(result []byte) ([]byte, []byte, string) {
	fields, ok := handoff.DecodeObject(result)
	signingText, _ := fields["signing"].(string)
	signatureText, _ := fields["signature"].(string)
	if !ok || len(fields) != 2 || signingText == "" || signatureText == "" || strings.ContainsAny(signingText+signatureText, "\r\n") {
		return nil, nil, "the result is not exactly a signing and a signature"
	}
	signing, errSigning := base64.StdEncoding.Strict().DecodeString(signingText)
	signature, errSignature := base64.StdEncoding.Strict().DecodeString(signatureText)
	if errSigning != nil || errSignature != nil || len(signature) != ed25519.SignatureSize {
		return nil, nil, "its signing or signature is not padded base64 of the right size"
	}
	return signing, signature, ""
}

// writeCertificateOnce publishes cert at path, which it never replaces: a
// regular file already holding exactly cert is left as it is, and anything
// else there, a link included, refuses certificate_out_exists.
func writeCertificateOnce(path string, cert *awid.TeamCertificate) error {
	err := publishCertificate(path, cert)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	exists := withErrorCode("certificate_out_exists", fmt.Errorf("%s already holds another file; the service keeps the certificate, so move the file and run again", path))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return exists
	}
	existing, err := os.ReadFile(path)
	encoded, encodeErr := awid.EncodeTeamCertificateFile(cert)
	if err != nil || encodeErr != nil || !bytes.Equal(existing, encoded) {
		return exists
	}
	return nil
}

// publishCertificate writes cert to a private file beside path and links it
// into place, which fails with os.ErrExist rather than replacing whatever
// path holds, even a file created after any earlier check.
func publishCertificate(path string, cert *awid.TeamCertificate) error {
	data, err := awid.EncodeTeamCertificateFile(cert)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".team-certificate-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	_, err = temp.Write(data)
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Link(temp.Name(), path)
}

func runTeamAdmit(cmd *cobra.Command, _ []string) error {
	request := admissionRequest{
		OperationID: strings.TrimSpace(teamAdmitOperationIDFlag), Team: strings.TrimSpace(teamAdmitTeamFlag),
		ChildID: strings.TrimSpace(teamAdmitMemberIDFlag), ChildKey: strings.TrimSpace(teamAdmitMemberKeyFlag),
		Alias: strings.TrimSpace(teamAdmitAliasFlag), PolicyVersion: teamAdmitPolicyVersionFlag,
		PolicyDigest: strings.TrimSpace(teamAdmitPolicyDigestFlag), CertificateOut: strings.TrimSpace(teamAdmitCertificateOutFlag),
	}
	for flag, value := range map[string]string{"--team": request.Team, "--member-key": request.ChildKey, "--alias": request.Alias,
		"--policy-digest": request.PolicyDigest, "--certificate-out": request.CertificateOut} {
		if value == "" {
			return usageError("%s is required", flag)
		}
	}
	if request.PolicyVersion < 1 {
		return usageError("--policy-version must be the positive version aw id team admission-policy reported")
	}
	profile, err := loadProtectedProfile()
	if err != nil {
		return err
	}
	binding, err := admissionBinding(profile, request.Team)
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	if identity.StableID == "" {
		return usageError("only a registered root (with a did:aw) can request an admission")
	}
	request.RootID, request.RootKey = identity.StableID, identity.DIDKey
	if err := announceOperationID(cmd, &request.OperationID, profile, admissionBody(profile, binding, request)); err != nil {
		return err
	}
	opts := handoff.GovernanceOptions{
		Request: profile.RequestOrigin, Human: profile.HumanOrigin,
		Sign: protectedRequesterSigner(profile, binding.Scope, identity), Notify: cmd.ErrOrStderr(),
	}
	request.Counts = func(ctx context.Context) (*handoff.AdmissionCounts, error) {
		read := handoff.GovernanceOptions{Request: profile.RequestOrigin, Sign: protectedRequesterSigner(profile, admissionPolicyScope(profile, request.Team), identity)}
		return handoff.ReadAdmissionCounts(ctx, read, profile.ServiceID, request.Team)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Admitting %s to %s through %s, operation %s\n", request.Alias, request.Team, profile.ServiceID, request.OperationID)
	report, err := admitMember(cmd.Context(), opts, profile, request)
	if err != nil {
		return err
	}
	printOutput(report, func(any) string {
		return fmt.Sprintf("Operation %s committed; %s's certificate for %s is at %s\n", request.OperationID, request.Alias, request.Team, request.CertificateOut)
	})
	return nil
}
