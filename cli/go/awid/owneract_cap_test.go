package awid

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/awebai/aw/strictjson"
)

func capSubject(cap any) map[string]any {
	return map[string]any{"app_id": "secrets", "installation_id": ownerInstall, "role": "secrets.owner", "cap": cap}
}

func TestCredentialCapUsesClosedOwnerActCodecAndOptInVocabulary(t *testing.T) {
	for _, cap := range []any{int64(1), int64(5), int64(9007199254740991), int64(2)} {
		fields := ownerAct("human-credential.cap-set", ownerAppAud, capSubject(cap), nonceFor(90))
		raw, signature, err := SignOwnerAct(ownerKey(ownerTeamSeed), fields)
		if err != nil {
			t.Fatalf("valid cap %v: %v", cap, err)
		}
		now, _ := time.Parse(time.RFC3339, ownerNow)
		options := OwnerActVerifyOptions{
			TeamID: ownerTeamIDValue, CurrentTeamKeyDID: ownerDID(ownerTeamSeed), Audience: ownerAppAud,
			Acts: []string{"human-credential.cap-set"}, ExpectedSubject: capSubject(cap), Now: now,
			NonceUsed: func(string) bool { return false },
		}
		verified, err := VerifyOwnerAct(raw, signature, options)
		if err != nil || verified.Act != "human-credential.cap-set" {
			t.Fatalf("verified %+v: %v", verified, err)
		}
		options.Acts = HumanRoleOwnerActs
		if _, err = VerifyOwnerAct(raw, signature, options); strictjson.Code(err) != "act_not_allowed" {
			t.Fatal("cap-set widened the legacy human-role verifier vocabulary")
		}
	}
}

func TestCredentialCapRefusesNonIntegersAndHolderOrExtraFields(t *testing.T) {
	for _, cap := range []any{nil, true, int64(0), int64(-1), int64(9007199254740992), "3", json.Number("1.5")} {
		if _, err := OwnerActSigningBytes(ownerAct("human-credential.cap-set", ownerAppAud, capSubject(cap), nonceFor(91))); err == nil {
			t.Fatalf("accepted invalid cap %#v", cap)
		}
	}
	for _, name := range []string{"principal", "signing_bytes", "team_id"} {
		subject := capSubject(int64(3))
		subject[name] = "extra"
		if _, err := OwnerActSigningBytes(ownerAct("human-credential.cap-set", ownerAppAud, subject, nonceFor(92))); strictjson.Code(err) != "unknown_field" {
			t.Fatalf("accepted extra subject member %s", name)
		}
	}
}
