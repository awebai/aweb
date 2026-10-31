package main

import (
	"errors"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestRoomReadErrorsDescribeKnownRefusalsAndPreserveOtherCauses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		id     string
		want   string
	}{
		{"removed", 403, `{"detail":"Agent not connected: no agent with did_key abc in team ops:example.test"}`, "", "You are no longer a member of ops:example.test, so you cannot read its room."},
		{"retired", 403, `{"detail":"Room requires current team membership"}`, "", "You are no longer a member of ops:example.test, so you cannot read its room."},
		{"missing exact post", 404, `{"detail":"Not found"}`, "post-id", "No room post post-id in your team."},
		{"server lacks rooms", 404, `{"detail":"Not Found"}`, "", ""},
		{"server lacks exact room API", 404, `{"detail":"Not Found"}`, "post-id", ""},
		{"grant scope", 403, `{"detail":"outside grant scope"}`, "", ""},
		{"grant rejected", 403, `{"detail":"identity grant rejected"}`, "", ""},
		{"registry unavailable", 503, `{"detail":"registry unavailable"}`, "post-id", ""},
		{"invalid certificate", 401, `{"detail":"Malformed certificate"}`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &awid.APIError{StatusCode: tc.status, Body: tc.body}
			got := roomReadError("ops:example.test", tc.id, original)
			if !errors.Is(got, original) || awid.DescribeError(got) != awid.DescribeError(original) {
				t.Fatal("lost original HTTP evidence")
			}
			if tc.want != "" && got.Error() != tc.want {
				t.Fatalf("got %q want %q", got.Error(), tc.want)
			}
			if tc.want == "" && got != original {
				t.Fatal("unrelated refusal disguised as missing membership or post")
			}
		})
	}
}
