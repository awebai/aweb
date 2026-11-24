package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type apiKeyMemberConnection struct {
	Request            apiKeyInitRequest
	ServerURL          string
	WorkspaceAPIKey    string
	Snapshot           map[string]bool
	TeamKeyObservation *awid.TeamCertificateKeyObservation
	TeamRegistryURL    string
}

// connectAPIKeyInitializedMember completes the installed membership while
// preserving the prepared recovery files before connection and the installed
// credentials after it (docs/identity.md#provisioned-members-and-encryption-discovery).
func connectAPIKeyInitializedMember(input apiKeyMemberConnection) (connectOutput, error) {
	req := input.Request
	out, err := initCertificateConnectWithOptions(req.WorkingDir, input.ServerURL, certificateConnectOptions{
		TeamKeyObservation:     input.TeamKeyObservation,
		TeamRegistryURL:        input.TeamRegistryURL,
		RegistryOperatorOrigin: operatorRegistryOrigin(input.TeamRegistryURL, ""),
		ContextFile:            req.ContextFile,
		EncryptionPublication:  req.EncryptionPublication,
		Role:                   strings.TrimSpace(req.Role),
		HumanName:              strings.TrimSpace(req.HumanName),
		AgentType:              strings.TrimSpace(req.AgentType),
		APIKey:                 strings.TrimSpace(input.WorkspaceAPIKey),
		IdentityHome:           strings.TrimSpace(req.IdentityHome),
	})
	if err != nil {
		var connected *connectedMemberSetupError
		if errors.As(err, &connected) {
			cleanupErr := removeAPIKeyPartialInit(awconfig.IdentityHome{Root: req.IdentityHome})
			return connectOutput{}, errors.Join(err, cleanupErr)
		}
		// Roll back everything this run created. The partial-init state (when
		// present) survives via the snapshot, so a retry resumes with the same
		// signing key the server already has on record.
		err = errors.Join(err, rollbackAwTree(awconfig.IdentityHome{Root: req.IdentityHome}, input.Snapshot))
		return connectOutput{}, fmt.Errorf("%w\n(local state from this attempt was rolled back; rerun the same command to resume)", err)
	}
	return out, nil
}
