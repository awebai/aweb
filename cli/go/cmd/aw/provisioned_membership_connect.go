package main

import (
	"errors"
	"strings"

	"github.com/awebai/aw/awconfig"
)

type provisionedTeamMembership struct {
	WorkingDir string
	Home       awconfig.IdentityHome
	AwebURL    string
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
	if strings.TrimSpace(request.WorkingDir) == "" || strings.TrimSpace(request.Home.Root) == "" {
		return errors.New("provisioning completion requires the member's working directory and identity home")
	}
	serviceURL := strings.TrimSpace(request.AwebURL)
	connectURL := serviceURL
	if connectURL == "" {
		connectURL = "<service-url>"
	}
	connectCommand := workspaceConnectCommandForIdentityHome(connectURL, request.Home.Root)
	if serviceURL == "" {
		return &provisionedMembershipIncompleteError{cause: &plainRefusal{text: "Membership is saved; the E2E key is NOT published by this provisioning attempt. Run `" + connectCommand + "` to connect and publish it."}}
	}
	_, err := initCertificateConnectWithOptions(request.WorkingDir, serviceURL, certificateConnectOptions{IdentityHome: request.Home.Root, EncryptionPublication: encryptionPublicationRequiredService})
	if err == nil {
		return nil
	}
	var publication *requiredEncryptionPublicationError
	if errors.As(err, &publication) {
		setupCommand := formatShellCommand([]string{"aw", "--identity-home", request.Home.Root, "id", "encryption-key", "setup"})
		return &provisionedMembershipIncompleteError{cause: &plainRefusal{text: "Membership is connected; E2E key publication is not confirmed. Run `" + setupCommand + "` to publish it.", err: err}}
	}
	return &provisionedMembershipIncompleteError{cause: &plainRefusal{text: "Membership is saved; the E2E key is NOT published by this provisioning attempt. Run `" + connectCommand + "` to connect and publish it.", err: err}}
}
