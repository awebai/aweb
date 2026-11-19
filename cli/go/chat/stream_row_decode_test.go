package chat

import (
	"testing"

	"github.com/awebai/aw/awid"
)

// A stream row that is not JSON cannot be verified, so it is shown as failed,
// as a row whose proof fields do not decode is.
func TestParseSSEEventMarksARowThatIsNotJSONAsFailed(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want awid.VerificationStatus
	}{
		{name: "not JSON", data: "hello from bob", want: awid.Failed},
		{name: "JSON object", data: `{"type":"message","body":"hello from bob"}`, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: tc.data})
			if ev.VerificationStatus != tc.want {
				t.Fatalf("verification_status=%q, want %q", ev.VerificationStatus, tc.want)
			}
		})
	}
}
