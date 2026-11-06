package awid

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSpawnIDTreeWirePreservesIssueAndPinnedMode(t *testing.T) {
	cases := []struct {
		name, raw string
		target    any
		field     string
	}{
		{"issue bundle", `{"id_chain":{"v":1,"type":"aweb.id-chain","certificates":[]}}`, &SpawnCreateInviteRequest{}, "id_chain"},
		{"issue binding", `{"invite_id":"spawn-invitation","id_tree":{"v":1,"issuer_id":"did:aw:issuer","domain":"ancestry.example","child_kind":"agent","mode":"self_custodial"}}`, &SpawnCreateInviteResponse{}, "id_tree"},
		{"accept mode", `{"v":1,"request_id":"creation","domain":"ancestry.example","parent":{"kind":"identity","id":"did:aw:issuer"},"mode":"host_managed"}`, &IDTreeCreationRequest{}, "mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(tc.raw), tc.target); err != nil {
				t.Fatal(err)
			}
			out, err := json.Marshal(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			var want, got map[string]any
			_ = json.Unmarshal([]byte(tc.raw), &want)
			_ = json.Unmarshal(out, &got)
			if !reflect.DeepEqual(got[tc.field], want[tc.field]) {
				t.Fatalf("lost %s in wire round trip", tc.field)
			}
		})
	}
}

func TestSpawnPreviewKeepsExplicitLegacyDistinctFromOmission(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		present bool
	}{
		{`{"id_tree":null}`, true}, {`{}`, false},
		{`{"id_tree":{"v":1,"issuer_id":"did:aw:issuer","domain":"example.com","child_kind":"agent","mode":"host_managed"}}`, true},
	} {
		var preview SpawnInvitePreviewResponse
		if err := json.Unmarshal([]byte(tc.raw), &preview); err != nil {
			t.Fatal(err)
		}
		if preview.IDTreePresent != tc.present {
			t.Fatal("lost explicit legacy distinction")
		}
	}
}

func TestSpawnAcceptRecoveryPreservesProtocolPresenceAndIntegers(t *testing.T) {
	for _, raw := range []string{`{}`, `{"id_chain":null,"registration_request":null}`, `{"id_chain":{"v":1,"type":"aweb.id-chain","certificates":[]},"registration_request":{"expected_head":null,"invitation_id":"child"}}`} {
		var first, second SpawnAcceptInviteResponse
		if err := json.Unmarshal([]byte(raw), &first); err != nil {
			t.Fatal(err)
		}
		saved, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(saved, &second); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first.IDTreeCreationResponse, second.IDTreeCreationResponse) {
			t.Fatal("recovery changed protocol or chain integer types")
		}
	}
}
