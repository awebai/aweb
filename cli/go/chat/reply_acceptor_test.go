package chat

import (
	"context"
	"testing"

	"github.com/awebai/aw/awid"
)

func waitedReply(t *testing.T, c *awid.Client, opts SendOptions) *SendResult {
	t.Helper()
	opts.Wait = 5
	result, err := Send(context.Background(), c, "alice", []string{"carol"}, "hello", opts, nil)
	if err != nil {
		t.Fatalf("the wait ended with an error: %v", err)
	}
	return result
}

func eventWithID(t *testing.T, result *SendResult, id string) Event {
	t.Helper()
	for _, ev := range result.Events {
		if ev.MessageID == id {
			return ev
		}
	}
	t.Fatalf("event %s missing from %+v", id, result.Events)
	return Event{}
}

// When the caller confirmed the target's DID, only a message signed by that
// identity is its reply; a message that only names the target is not.
func TestSendAcceptsOnlyTheConfirmedTargetsReply(t *testing.T) {
	t.Parallel()
	reader, carol, other := newParityKey(t), newParityKey(t), newParityKey(t)
	impostor := signedParityRow(t, other, &awid.MessageEnvelope{
		From: "carol", FromDID: other.did, To: "alice", ToDID: reader.did, Type: "chat",
		Body: "not from carol", Timestamp: "2026-11-18T00:00:00Z",
		MessageID: "50000000-0000-4000-8000-000000000001", ConversationID: paritySessionID,
	}, map[string]any{"from_agent": "carol"})
	genuine := signedParityRow(t, carol, &awid.MessageEnvelope{
		From: "carol", FromDID: carol.did, To: "alice", ToDID: reader.did, Type: "chat",
		Body: "done", Timestamp: "2026-11-18T00:00:01Z",
		MessageID: "50000000-0000-4000-8000-0000000000ff", ConversationID: paritySessionID,
	}, map[string]any{"from_agent": "carol"})

	result := waitedReply(t, parityReader(t, parityServer(t, []map[string]any{impostor}, genuine), reader, carol), SendOptions{RecipientDID: carol.did})

	if got := eventWithID(t, result, "50000000-0000-4000-8000-000000000001").VerificationStatus; got == awid.Failed || got == awid.IdentityMismatch {
		t.Fatalf("impostor status=%s: this case is about the confirmed DID, not a failed verification", got)
	}
	if result.Status != "replied" || result.Reply != "done" {
		t.Fatalf("status=%s reply=%q, want carol's reply", result.Status, result.Reply)
	}
}
