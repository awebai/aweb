package main

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
)

var protectedHistoryID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var protectedServiceID = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)

func requireLegacyInviteTeam(team *awid.RegistryTeam) error {
	unavailable := func() error {
		return withErrorCode("protected_state_unavailable", fmt.Errorf("the configured registry did not provide an explicit valid protection state"))
	}
	if team == nil {
		return unavailable()
	}
	fields, ok := handoff.DecodeObject(team.Protection)
	if !ok {
		return unavailable()
	}
	switch fields["mode"] {
	case "legacy":
		if len(fields) != 1 {
			return unavailable()
		}
		return nil
	case "protected":
		if len(fields) != 5 {
			return unavailable()
		}
		service, _ := fields["service_id"].(string)
		history, _ := fields["history_id"].(string)
		did, _ := fields["service_did_key"].(string)
		generation, ok := fields["generation"].(json.Number)
		number, err := generation.Int64()
		if !ok || err != nil || number <= 0 || number > 1<<53-1 || !protectedServiceID.MatchString(service) || !protectedHistoryID.MatchString(history) {
			return unavailable()
		}
		if _, err := awid.ExtractPublicKey(did); err != nil || did == team.TeamDIDKey {
			return unavailable()
		}
		return withErrorCode("protected_admission_required", fmt.Errorf("team %s requires the configured protected service/root admission path (--protected-profile <profile>)", team.TeamID))
	default:
		return unavailable()
	}
}
