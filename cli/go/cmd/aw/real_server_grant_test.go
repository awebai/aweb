package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
)

func TestRealServerGrantMissNamesTheSelectedTeam(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "grant-owner")
	const missingID = "00000000-0000-4000-8000-000000000001"
	want := fmt.Sprintf("Grant %s was not found in team %s. Run `aw --team %s id grant list` with the same identity home to choose a grant ID.", missingID, world.TeamID, world.TeamID)
	for _, test := range []struct {
		verb       string
		httpStatus int
		detail     string
	}{
		{verb: "show"},
		{verb: "revoke", httpStatus: 404, detail: "grant not found"},
	} {
		t.Run(test.verb, func(t *testing.T) {
			out, err := world.runInIdentityHome(member.Home, "id", "grant", test.verb, missingID)
			if err == nil {
				t.Fatalf("missing grant succeeded: %s", out)
			}
			var refused cliErrorEnvelope
			if err := json.Unmarshal([]byte(out), &refused); err != nil {
				t.Fatalf("grant refusal is not JSON: %v\n%s", err, out)
			}
			if refused.Error.Code != string(grantNotFound) || refused.Error.Message != want || refused.Error.HTTPStatus != test.httpStatus || refused.Error.Detail != test.detail {
				t.Fatalf("grant refusal lost its selected-team recovery or original metadata: %+v", refused.Error)
			}
		})
	}

	// A miss must not hide or break the neighboring supported grant lifecycle.
	out := world.requireCommand(t, member.Home, "id", "grant", "mint", "--ttl", "5m", "--scope", "coord.read", "--out", filepath.Join(t.TempDir(), "grant"))
	var minted grantMintOutput
	if err := json.Unmarshal([]byte(out), &minted); err != nil || minted.GrantID == "" || minted.TeamID != world.TeamID {
		t.Fatalf("real grant mint did not return its team and ID: %v\n%s", err, out)
	}
	out = world.requireCommand(t, member.Home, "id", "grant", "show", minted.GrantID)
	var shown struct {
		GrantID string `json:"grant_id"`
		TeamID  string `json:"team_id"`
	}
	if err := json.Unmarshal([]byte(out), &shown); err != nil || shown.GrantID != minted.GrantID || shown.TeamID != world.TeamID {
		t.Fatalf("real grant show lost the minted grant: %v\n%s", err, out)
	}
	world.requireCommand(t, member.Home, "id", "grant", "revoke", minted.GrantID)
}
