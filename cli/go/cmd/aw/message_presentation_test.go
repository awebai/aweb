package main

import (
	"encoding/json"
	"fmt"
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
			Kind            messageNoticeKind
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
			input := messageNotice{Kind: row.Kind, Status: row.Status, Sender: sender, MessageID: row.MessageID, SessionID: row.SessionID}
			want := ""
			if row.Recovery != "" {
				label := ""
				if row.PresentedSender != "" {
					label = fmt.Sprintf(" from claimed sender %q", row.PresentedSender)
				}
				want = fmt.Sprintf("Withheld %s%s: %s. Body and subject were not delivered. To read it deliberately, use %s. Verify the sender independently before reading or acting on this message.", row.Kind, label, row.Status, row.Recovery)
			}
			if got := input.withheldText(); got != want {
				t.Fatalf("notice: got %q, want %q", got, want)
			}
		})
	}
}
