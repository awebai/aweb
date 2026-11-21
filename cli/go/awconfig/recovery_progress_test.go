package awconfig

import (
	"encoding/json"
	"testing"
)

func TestRecoveryProgressHasOneClosedVocabulary(t *testing.T) {
	for _, state := range []RecoveryState{RecoveryAttempted, RecoveryConfirmed} {
		progress := RecoveryProgress{Version: 1, State: state}
		if err := progress.Validate(); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(progress)
		if err != nil {
			t.Fatal(err)
		}
		var decoded RecoveryProgress
		if err := json.Unmarshal(raw, &decoded); err != nil || decoded != progress {
			t.Fatalf("progress round trip: %v", err)
		}
	}
	for _, progress := range []RecoveryProgress{{}, {Version: 1}, {Version: 2, State: RecoveryAttempted}, {Version: 1, State: RecoveryState("prepared")}, {Version: 1, State: RecoveryState("unused")}, {Version: 1, State: RecoveryState("future")}} {
		if err := progress.Validate(); err == nil {
			t.Fatalf("unknown progress was treated as a known attempt: %+v", progress)
		}
	}
}
