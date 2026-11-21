package main

import "testing"

func TestInitConnectIdentityUsesInputsAndNeverInfersHumanKind(t *testing.T) {
	t.Setenv("AWEB_ROLE_NAME", "environment-role")
	t.Setenv("AWEB_ROLE", "older-role")
	t.Setenv("AWEB_AGENT_TYPE", "human")
	t.Setenv("AWEB_HUMAN", "environment-display-name")
	previousRole, previousHuman, previousType := initRole, initHumanName, initAgentType
	initRole, initHumanName, initAgentType = "ambient-role", "ambient-human", "ambient-runtime"
	t.Cleanup(func() { initRole, initHumanName, initAgentType = previousRole, previousHuman, previousType })
	created := initConnectIdentity(initIdentityInput{Role: " explicit-role ", HumanName: " named-person ", AgentType: " human "})
	if created.Role != "explicit-role" || created.HumanName != "named-person" || created.AgentType != "agent" {
		t.Fatalf("input replaced by command globals or an unverified human hint: %+v", created)
	}
	defaults := initConnectIdentity(initIdentityInput{})
	if defaults.Role != "environment-role" || defaults.HumanName != "" || defaults.AgentType != "agent" {
		t.Fatalf("incorrect defaults or inferred human: %+v", defaults)
	}
	custom := initConnectIdentity(initIdentityInput{AgentType: " custom-runtime "})
	if custom.AgentType != "custom-runtime" || custom.HumanName != "" {
		t.Fatalf("custom runtime: %+v", custom)
	}
}
