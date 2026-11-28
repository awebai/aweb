package main

import "testing"

func TestInitConnectIdentityUsesInputsAndNeverInfersHumanKind(t *testing.T) {
	t.Setenv("AWEB_AGENT_TYPE", "human")
	t.Setenv("AWEB_HUMAN", "environment-display-name")
	previousHuman, previousType := initHumanName, initAgentType
	initHumanName, initAgentType = "ambient-human", "ambient-runtime"
	t.Cleanup(func() { initHumanName, initAgentType = previousHuman, previousType })
	created := initConnectIdentity(initIdentityInput{HumanName: " named-person ", AgentType: " human "})
	if created.HumanName != "named-person" || created.AgentType != "agent" {
		t.Fatalf("input replaced by command globals or an unverified human hint: %+v", created)
	}
	defaults := initConnectIdentity(initIdentityInput{})
	if defaults.HumanName != "" || defaults.AgentType != "agent" {
		t.Fatalf("incorrect defaults or inferred human: %+v", defaults)
	}
	custom := initConnectIdentity(initIdentityInput{AgentType: " custom-runtime "})
	if custom.AgentType != "custom-runtime" || custom.HumanName != "" {
		t.Fatalf("custom runtime: %+v", custom)
	}
}
