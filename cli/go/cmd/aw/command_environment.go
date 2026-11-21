package main

import (
	"os"
	"strings"
)

// Only human identities inherit a display name from the environment. An agent
// name must be supplied explicitly; a machine login does not identify its human.
func resolveHumanNameValue(value, agentType string) string {
	if v := strings.TrimSpace(value); v != "" || agentType != "human" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_HUMAN")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_HUMAN_NAME")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("USER")); v != "" {
		return v
	}
	return "developer"
}

func resolveRequestedRole(explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_ROLE_NAME")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("AWEB_ROLE"))
}
