package awid

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/awebai/aw/strictjson"
)

func teamGovernanceSubject(act string) map[string]any {
	subject := map[string]any{"team_id": ownerTeamIDValue, "expected_revision": json.Number("3")}
	if act == "team.owner.change" {
		subject["old_owners"] = []any{"did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"}
		subject["new_owners"] = []any{"did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"}
	} else {
		subject["old_permissions"] = []any{}
		subject["new_permissions"] = []any{"human-role.revoke/default", "team.agent.admit/default"}
	}
	return subject
}

func TestTeamGovernanceIsAnOptInTypedOwnerActVocabulary(t *testing.T) {
	for _, act := range []string{"team.owner.change", "team.controller-permissions.change"} {
		subject, err := ValidateOwnerActSubject(act, teamGovernanceSubject(act))
		if err != nil {
			t.Fatalf("%s: %v", act, err)
		}
		if subject["expected_revision"] != int64(3) {
			t.Fatal("saved revision was not normalized")
		}
		raw, signature, err := SignOwnerAct(ownerKey(ownerTeamSeed), ownerAct(act, ownerCoreAud, subject, nonceFor(94)))
		if err != nil {
			t.Fatal(err)
		}
		now, _ := time.Parse(time.RFC3339, ownerNow)
		options := OwnerActVerifyOptions{
			TeamID: ownerTeamIDValue, CurrentTeamKeyDID: ownerDID(ownerTeamSeed), Audience: ownerCoreAud,
			Acts: TeamGovernanceOwnerActs, ExpectedSubject: subject, Now: now,
			NonceUsed: func(string) bool { return false },
		}
		if _, err := VerifyOwnerAct(raw, signature, options); err != nil {
			t.Fatal(err)
		}
		for _, oldVocabulary := range [][]string{CoreOwnerActs, AppOwnerActs, HumanRoleOwnerActs, LogsOwnerActs} {
			options.Acts = oldVocabulary
			if _, err := VerifyOwnerAct(raw, signature, options); strictjson.Code(err) != "act_not_allowed" {
				t.Fatalf("%s widened a released verifier: %v", act, err)
			}
		}
	}
}

func TestTeamGovernanceSubjectsRefuseExtraFieldsInvalidRevisionsAndUnorderedSets(t *testing.T) {
	for _, act := range []string{"team.owner.change", "team.controller-permissions.change"} {
		for _, badRevision := range []any{true, int64(0), int64(-1), json.Number("3.0"), json.Number("9007199254740992")} {
			subject := teamGovernanceSubject(act)
			subject["expected_revision"] = badRevision
			if _, err := ValidateOwnerActSubject(act, subject); err == nil {
				t.Fatalf("%s accepted revision %#v", act, badRevision)
			}
		}
		subject := teamGovernanceSubject(act)
		subject["principal"] = "agent"
		if _, err := ValidateOwnerActSubject(act, subject); strictjson.Code(err) != "unknown_field" {
			t.Fatalf("%s accepted an unbound actor: %v", act, err)
		}
		field, item := "new_owners", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"
		if act == "team.controller-permissions.change" {
			field, item = "new_permissions", "team.agent.admit/default"
		}
		for _, invalid := range []any{[]any{item, item}, []any{"*"}, "*", []any{false}} {
			subject := teamGovernanceSubject(act)
			subject[field] = invalid
			if _, err := ValidateOwnerActSubject(act, subject); err == nil {
				t.Fatalf("%s accepted set %#v", act, invalid)
			}
		}
	}
}
