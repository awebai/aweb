package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestMessagePresentationVector(t *testing.T) {
	data, err := os.ReadFile("../../../../test-vectors/message-presentation-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Version int
		Cases   []struct {
			Name            string
			Status          awid.VerificationStatus
			Trusted         bool
			Sender          string
			FromAddress     string `json:"from_address"`
			PresentedSender string `json:"presented_sender"`
			MessageID       string `json:"message_id"`
			SessionID       string `json:"session_id"`
			Recovery        string
		}
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Version != 1 || len(vector.Cases) == 0 {
		t.Fatal("missing message presentation cases")
	}
	for _, row := range vector.Cases {
		t.Run(row.Name, func(t *testing.T) {
			if got := row.Status.Trusted(); got != row.Trusted {
				t.Fatalf("trusted: got %v, want %v", got, row.Trusted)
			}
			sender := row.Sender
			if row.FromAddress != "" {
				sender = row.FromAddress
			}
			if got := claimedSenderIdentifier(sender); got != row.PresentedSender {
				t.Fatalf("claimed sender: got %q, want %q", got, row.PresentedSender)
			}
		})
	}
}
