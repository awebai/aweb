package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func hostedJoinFromRetryError(cause error, cmd *cobra.Command, prior *initInviteRecovery) error {
	args := hostedInviteRetryPrefix(cmd, nil)
	args = append(args, "init", "--join-from", firstNonEmpty(prior.SourceHome, prior.Source),
		"--join-team", prior.TeamID, "--name", prior.Alias)
	args = appendExplicitRetryFlags(args, cmd, "global", "persistent",
		"role-name", "role", "human-name", "agent-type", "write-context", "inject-docs", "do-not-touch-agents-md", "print-exports")
	if cmd.Flags().Changed("awid-registry") {
		if registry := recoveryServiceURL(initAWIDRegistry); registry != "" {
			args = append(args, "--awid-registry", registry)
		}
	}
	return hostedInviteRetryError(cause, args, "")
}

func hostedTokenRetryError(cause error, cmd *cobra.Command, command []string, name string, environment []string) error {
	args := append(hostedInviteRetryPrefix(cmd, environment), command...)
	file, _ := cmd.Flags().GetString("token-file")
	file = strings.TrimSpace(file)
	input := " with the original invitation on stdin"
	if file == "" {
		args = append(args, "--token-stdin")
	} else {
		if absolute, err := filepath.Abs(file); err == nil {
			file = absolute
		}
		args = append(args, "--token-file", file)
		input = ""
	}
	if name != "" {
		args = append(args, "--name", name)
	}
	args = appendExplicitRetryFlags(args, cmd, "parent", "local", "global", "address", "no-address", "no-connect", "harness")
	// The deprecated init spelling selects the same scope as --global.
	if cmd.Flags().Changed("persistent") && !cmd.Flags().Changed("global") && initGlobal {
		args = append(args, "--global")
	}
	return hostedInviteRetryError(cause, args, input)
}

func hostedInviteRetryPrefix(cmd *cobra.Command, environment []string) []string {
	var args []string
	if len(environment) != 0 {
		args = append([]string{"env"}, environment...)
	}
	return appendExplicitRetryFlags(append(args, "aw"), cmd, "identity-home")
}

func initInviteServiceEnvironment(cmd *cobra.Command, inviteOrigin string) []string {
	var environment []string
	if inviteOrigin == "" && (cmd.Flags().Changed("url") || cmd.Flags().Changed("aweb-url")) {
		if service := recoveryServiceURL(resolveInitAwebURLOverride()); service != "" {
			environment = append(environment, "AWEB_URL="+service)
		}
	}
	if cmd.Flags().Changed("awid-registry") {
		if registry := recoveryServiceURL(initAWIDRegistry); registry != "" {
			environment = append(environment, "AWID_REGISTRY_URL="+registry)
		}
	}
	return environment
}

// Recovery output can carry a service route. URL credentials stay in config.
func recoveryServiceURL(raw string) string {
	value, err := parseAwebSelectionURL(raw)
	if err != nil || value.User != nil || value.Hostname() == "" {
		return ""
	}
	return awebSelectionURLString(value)
}

func appendExplicitRetryFlags(args []string, cmd *cobra.Command, names ...string) []string {
	for _, name := range names {
		flag := cmd.Flags().Lookup(name)
		if flag == nil || !flag.Changed {
			continue
		}
		value := flag.Value.String()
		if flag.Value.Type() != "bool" {
			args = append(args, "--"+name, value)
		} else if value == "true" {
			args = append(args, "--"+name)
		} else {
			args = append(args, "--"+name+"="+value)
		}
	}
	return args
}

func hostedInviteRetryError(cause error, args []string, input string) error {
	return fmt.Errorf("%w\nKeep this identity home. When the service is ready, run `%s` from the same directory with the same service configuration%s.",
		cause, formatShellCommand(args), input)
}
