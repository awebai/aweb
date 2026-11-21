package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type initSignupResumeInput struct {
	Command    *cobra.Command
	WorkingDir string
	Invite     initInviteInput
	Identity   certificateConnectOptions
}

// resumeSignupFromInit gives retained signup precedence over reconnect and new
// authority selection. This continues the original creation, never a new key,
// handle, invitation or API-key bootstrap in its recovery home.
func resumeSignupFromInit(input initSignupResumeInput) (initDispatchResult, error) {
	state, err := loadHostedSignupRecovery(input.WorkingDir)
	if err != nil {
		return initDispatchComplete, err
	}
	if state == nil {
		return initDispatchDeferred, nil
	}
	for _, name := range initOutcomeFlagNames(input.Invite) {
		if name != "--new-account" {
			return initDispatchComplete, errors.New("this home has a retained signup; run aw init to resume it before selecting another creation or join")
		}
	}
	if resolveInitAPIKey() != "" {
		return initDispatchComplete, errors.New("this home has a retained signup; unset the supplied API key and run aw init to resume it")
	}
	selected, err := identityHomeForDir(input.WorkingDir)
	if err != nil {
		return initDispatchComplete, err
	}
	if selected.External() && filepath.Clean(selected.Root) != filepath.Clean(awconfig.WorktreeIdentityHome(input.WorkingDir)) {
		return initDispatchComplete, errors.New("this home has a retained signup; select its original identity home to resume it")
	}
	request, _, err := state.identity()
	if err != nil {
		return initDispatchComplete, err
	}
	if input.Command.Flags().Changed("global") && initGlobal != (request.DIDAW != "") {
		return initDispatchComplete, errors.New("signup retry changed the original identity scope")
	}
	if raw := firstNonEmptyString(initAWIDRegistry, os.Getenv("AWID_REGISTRY_URL")); raw != "" {
		selectedRegistry, err := awid.CanonicalRegistryServerOrigin(raw)
		if err != nil {
			return initDispatchComplete, err
		}
		if selectedRegistry != state.Context.RegistryURL {
			return initDispatchComplete, errors.New("signup retry changed the original registry")
		}
	}
	baseURL := ""
	if firstNonEmptyString(initAwebURL, initURL, os.Getenv("AWEB_URL"), serverFlag) != "" {
		baseURL, err = resolveInitAwebURL()
		if err != nil {
			return initDispatchComplete, err
		}
	}
	result, err := resumeHostedSignup(guidedOnboardingRequest{
		ContextFile: input.Identity.ContextFile,
		WorkingDir:  input.WorkingDir, PromptIn: os.Stdin, PromptOut: input.Command.ErrOrStderr(), BaseURL: baseURL,
		Username: strings.TrimSpace(initUsername), Alias: firstNonEmptyString(initName, initAlias),
		Role: input.Identity.Role, HumanName: input.Identity.HumanName, AgentType: input.Identity.AgentType,
		Global: initGlobal, InboundMode: canonicalInitInboundModeForWire(initInboundMode),
		InjectAgentDocs: initInjectDocs, DoNotTouchAgentsMD: initDoNotTouchAgentsMD, NonInteractive: !initIsTTY() || jsonFlag,
	}, state)
	if err == nil && !jsonFlag {
		initPrintGuidedOnboardingReady(result)
	}
	return initDispatchComplete, err
}
