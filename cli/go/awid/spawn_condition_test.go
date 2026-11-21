package awid

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSpawnInviteConditionAndMembershipChainWire(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		target      any
		field       string
	}{
		{"creation condition", `{"for_human":"did:aw:person"}`, &SpawnCreateInviteRequest{}, "for_human"},
		{"resolved condition", `{"for_human":"did:aw:person"}`, &SpawnCreateInviteResponse{}, "for_human"},
		{"preview condition", `{"for_human":"did:aw:person"}`, &SpawnInvitePreviewResponse{}, "for_human"},
		{"unconditioned preview", `{"for_human":null}`, &SpawnInvitePreviewResponse{}, "for_human"},
		{"independent chain", `{"id_chain":{"v":1,"type":"aweb.id-chain","certificates":[]}}`, &SpawnAcceptInviteRequest{}, "id_chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(tc.input), tc.target); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			var want, got map[string]json.RawMessage
			json.Unmarshal([]byte(tc.input), &want)
			json.Unmarshal(raw, &got)
			var gotValue, wantValue any
			json.Unmarshal(got[tc.field], &gotValue)
			json.Unmarshal(want[tc.field], &wantValue)
			_, present := got[tc.field]
			if !present || !reflect.DeepEqual(gotValue, wantValue) {
				t.Fatalf("lost %s: %s", tc.field, raw)
			}
		})
	}
}

func TestReleasedSpawnInviteRequestOmitsUnprovidedChain(t *testing.T) {
	got, err := json.Marshal(SpawnAcceptInviteRequest{Token: "fixture", DID: "did:key:member"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"token":"fixture","did":"did:key:member"}`; string(got) != want {
		t.Fatalf("released unconditioned request = %s, want %s", got, want)
	}
}
