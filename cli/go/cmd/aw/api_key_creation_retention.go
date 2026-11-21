package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
)

// apiKeyCreationRecoveryAdvice names the child operation's directory when its
// caller runs in the creator's directory. It never includes the API key.
func apiKeyCreationRecoveryAdvice(request apiKeyInitRequest, cause error) error {
	if !retainUnfinishedProvisioningIdentity(cause) {
		return cause
	}
	var connected *connectedMemberSetupError
	if errors.As(cause, &connected) {
		var publication *requiredEncryptionPublicationError
		if errors.As(cause, &publication) {
			setup := formatShellCommand([]string{"aw", "--identity-home", request.IdentityHome, "id", "encryption-key", "setup"})
			return fmt.Errorf("%w\nThe member is connected and its credentials are retained at %s. Run `%s` to confirm E2E key publication; do not repeat identity creation.", cause, request.IdentityHome, setup)
		}
		connect := formatShellCommand([]string{"aw", "--identity-home", request.IdentityHome, "workspace", "connect", "--service", "<original-service-url>"})
		return fmt.Errorf("%w\nThe connected member is retained at %s. Repair the reported local setup error, then run `%s` with its original service URL; do not repeat identity creation.", cause, request.IdentityHome, connect)
	}
	if remedy, known := workspaceInitRefusalRemedies[errorCodeOf(cause)]; known && remedy.changesContext {
		return fmt.Errorf("%w\nThe original identity material remains at %s; keep it for reconciliation.", cause, request.IdentityHome)
	}
	args := []string{"aw", "init"}
	if request.RegistryURL != "" {
		args = append(args, "--awid-registry", request.RegistryURL)
	}
	if request.Global {
		args = append(args, "--global", "--name", request.Name)
	} else {
		args = append(args, "--alias", request.Alias)
	}
	for _, setting := range []struct{ flag, value string }{
		{"--role-name", request.Role}, {"--human-name", request.HumanName}, {"--agent-type", request.AgentType}, {"--inbound-mode", request.InboundMode},
	} {
		if strings.TrimSpace(setting.value) != "" {
			args = append(args, setting.flag, setting.value)
		}
	}
	if request.ContextFile == workspaceContextPreserve {
		args = append(args, "--write-context=false")
	}
	advice := fmt.Errorf("%w\nThe retained creation directory is %s. From there, with the original service URL, API key and registry selection (AWEB_URL, AWEB_API_KEY and AWID_REGISTRY_URL), run `%s` to finish this same identity before resuming roster/worktree setup.", cause, request.WorkingDir, formatShellCommand(args))
	if request.EncryptionPublication == encryptionPublicationRequiredService {
		setup := formatShellCommand([]string{"aw", "--identity-home", request.IdentityHome, "id", "encryption-key", "setup"})
		return fmt.Errorf("%w After connecting, run `%s` to confirm E2E key publication.", advice, setup)
	}
	return advice
}

type apiKeyInitRecoveryState uint8

const (
	apiKeyInitRecoverable apiKeyInitRecoveryState = iota
	apiKeyInitReconciliationOnly
)

type apiKeyInitFailure struct {
	Cause error
	Home  awconfig.IdentityHome
	State apiKeyInitRecoveryState
}

// finalizeAPIKeyInitFailure preserves the prepared key/request through outer
// roster and worktree cleanup. Registration or submission may already have
// happened; a response status does not prove that this home is disposable.
func finalizeAPIKeyInitFailure(input apiKeyInitFailure) error {
	if input.Cause == nil {
		return nil
	}
	cause := input.Cause
	if input.State == apiKeyInitRecoverable {
		info, stateErr := os.Lstat(apiKeyPartialInitPath(input.Home))
		if stateErr == nil && info.Mode().IsRegular() {
			cause = fmt.Errorf("%w\n%s", cause, partialInitGuidance(cause))
		} else if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
			cause = errors.Join(cause, fmt.Errorf("inspect retained API-key init state: %w", stateErr))
		}
	}
	return retainIdentityForRecovery(cause)
}
