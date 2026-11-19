package wake

import (
	"testing"

	"github.com/awebai/aw/awid"
)

// deliverFixtureStreamEvent constructs the fixture's accepted stream identity,
// then exercises the same dispatcher the production stream uses.
func deliverFixtureStreamEvent(t *testing.T, broker *Broker, identityHome string, event awid.AgentEvent) {
	t.Helper()
	teamID, err := effectiveTeamID(identityHome, "")
	if err != nil {
		t.Fatalf("resolve fixture stream team: %v", err)
	}
	key, err := bindingKey(identityHome, teamID)
	if err != nil {
		t.Fatalf("resolve fixture stream key: %v", err)
	}
	broker.dispatchStream(key, event)
}
