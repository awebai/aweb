package chat

import (
	"context"
	"testing"

	"github.com/awebai/aw/awid"
)

// The chat package is public Go API (cli/go/README.md "Go Library"). These
// are its entry points as released in aw-v1.36.58; a change that breaks one
// fails to compile here (released-clients-are-a-permanent-constraint).
var (
	_ func(context.Context, *awid.Client, string, string, ...bool) (*ExtendWaitResult, error) = ExtendWait
	_ string                                                                                  = Event{}.Type
	_ string                                                                                  = SendResult{}.Status
	_ bool                                                                                    = SendOptions{}.EncryptE2EE
	_ bool                                                                                    = ExtendWaitOptions{}.EncryptE2EE
)

func TestReleasedEncryptE2EERequiresEncryption(t *testing.T) {
	if got := (SendOptions{EncryptE2EE: true}).Encryption(); got != E2EERequired {
		t.Fatalf("SendOptions{EncryptE2EE: true} chooses %v, want E2EERequired", got)
	}
	if got := (ExtendWaitOptions{EncryptE2EE: true}).Encryption(); got != E2EERequired {
		t.Fatalf("ExtendWaitOptions{EncryptE2EE: true} chooses %v, want E2EERequired", got)
	}
	if got := (SendOptions{E2EE: E2EEPlaintext}).Encryption(); got != E2EEPlaintext {
		t.Fatalf("an explicit E2EE choice was overridden: %v", got)
	}
}
