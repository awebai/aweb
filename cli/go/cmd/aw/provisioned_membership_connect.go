package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type provisionedTeamMembership struct {
	WorkingDir string
	Home       awconfig.IdentityHome
	AwebURL    string
	Role       string
	HumanName  string
	AgentType  string
}

// provisionedMembershipIncompleteError carries the already admitted home's
// recovery boundary through roster creation, which must not remove its key.
type provisionedMembershipIncompleteError struct{ cause error }

func (err *provisionedMembershipIncompleteError) Error() string { return err.cause.Error() }
func (err *provisionedMembershipIncompleteError) Unwrap() error { return err.cause }

// completeProvisionedTeamMembership uses the normal admission before service
// publication (docs/identity.md#provisioned-members-and-encryption-discovery).
// Its explicit home is the produced member, independently of the operator's
// selected identity. Failure retains the already accepted certificate and key.
func completeProvisionedTeamMembership(request provisionedTeamMembership) error {
	_, err := connectProvisionedTeamMembership(request)
	return err
}

// connectProvisionedTeamMembership returns the admitted member result for
// callers that also complete git-worktree setup; the publication rule and
// precise recovery errors are shared with roster provisioning.
func connectProvisionedTeamMembership(request provisionedTeamMembership) (connectOutput, error) {
	if strings.TrimSpace(request.WorkingDir) == "" || strings.TrimSpace(request.Home.Root) == "" {
		return connectOutput{}, errors.New("provisioning completion requires the member's working directory and identity home")
	}
	serviceURL := strings.TrimSpace(request.AwebURL)
	connectURL := serviceURL
	if connectURL == "" {
		connectURL = "<service-url>"
	}
	connectCommand := workspaceConnectCommandForIdentityHome(connectURL, request.Home.Root)
	if serviceURL == "" {
		return connectOutput{}, &provisionedMembershipIncompleteError{cause: &plainRefusal{text: "Membership is saved; the E2E key is NOT published by this provisioning attempt. Run `" + connectCommand + "` to connect and publish it."}}
	}
	output, err := initCertificateConnectWithOptions(request.WorkingDir, serviceURL, certificateConnectOptions{IdentityHome: request.Home.Root, Role: request.Role, HumanName: request.HumanName, AgentType: request.AgentType, EncryptionPublication: encryptionPublicationRequiredService})
	if err == nil {
		return output, nil
	}
	var publication *requiredEncryptionPublicationError
	if errors.As(err, &publication) {
		setupCommand := formatShellCommand([]string{"aw", "--identity-home", request.Home.Root, "id", "encryption-key", "setup"})
		return connectOutput{}, &provisionedMembershipIncompleteError{cause: &plainRefusal{text: "Membership is connected; E2E key publication is not confirmed. Run `" + setupCommand + "` to publish it.", err: err}}
	}
	return connectOutput{}, &provisionedMembershipIncompleteError{cause: &plainRefusal{text: "Membership is saved; the E2E key is NOT published by this provisioning attempt. Run `" + connectCommand + "` to connect and publish it.", err: err}}
}

type provisionedRecordFailure struct {
	Home        awconfig.IdentityHome
	Certificate awid.TeamCertificate
	RegistryURL string
	AwebURL     string
	Cause       error
}

// retainProvisionedRecordFailure protects an accepted member even when its
// local membership row could not be saved. Repair uses the installed exact
// certificate, followed by normal admission; no replacement key is created.
func retainProvisionedRecordFailure(input provisionedRecordFailure) error {
	path, err := awconfig.TeamCertificatePathFromIdentityHome(input.Home.Root, input.Certificate.Team)
	if err != nil {
		return &provisionedMembershipIncompleteError{cause: fmt.Errorf("accepted member retained in %s; repair its local storage before continuing: %w", input.Home.Root, errors.Join(input.Cause, err))}
	}
	args := []string{"aw", "--identity-home", input.Home.Root, "id", "team", "install-cert", "--certificate", path}
	if input.RegistryURL != "" {
		args = append(args, "--registry", input.RegistryURL)
	}
	service := input.AwebURL
	if service == "" {
		service = "<service-url>"
	}
	return &provisionedMembershipIncompleteError{cause: &plainRefusal{text: fmt.Sprintf("Accepted membership is retained in %s; local recording failed: %v. Repair that local file error, then run `%s` and `%s` to record the same certificate and connect. Keep this home's key and certificate.", input.Home.Root, input.Cause, formatShellCommand(args), workspaceConnectCommandForIdentityHome(service, input.Home.Root)), err: input.Cause}}
}
