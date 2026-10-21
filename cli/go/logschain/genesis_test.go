package logschain

import (
	"testing"
)

// The vector pins every report; what it cannot hold is a genesis that does
// not verify at all, which refuses the whole check.

func intactCase(t *testing.T) (Genesis, []StoredEvent, map[string]bool) {
	t.Helper()
	for _, c := range loadVector(t).ChainCases {
		if c.Name != "intact_chain_of_three_producers" {
			continue
		}
		events := make([]StoredEvent, len(c.Events))
		for i, e := range c.Events {
			events[i] = StoredEvent{
				Link: Link{
					ChainEpoch: e.Link.ChainEpoch, TeamID: e.Link.TeamID, TeamSeq: e.Link.TeamSeq,
					PrevEventHash: e.Link.PrevEventHash, ReceivedAt: e.Link.ReceivedAt, Hook: e.Link.Hook,
					ProducerOrigin: e.Link.ProducerOrigin, ContentCommitment: e.Link.ContentCommitment,
				},
				EventHash: e.EventHash,
				Content: &Content{
					Salt: unb64(t, e.Content.Salt), SigningBytes: unb64(t, e.Content.SigningBytes),
					Signature: e.Content.Signature, ProducerDIDKey: e.Content.ProducerDIDKey,
				},
			}
		}
		return c.Genesis.genesis(), events, keySet(c.ReceiptKeys)
	}
	t.Fatal("the vector has no intact chain case")
	return Genesis{}, nil, nil
}

func TestAGenesisThatDoesNotHoldIsRefused(t *testing.T) {
	genesis, events, keys := intactCase(t)
	genesis.PreviousCheckpointSHA256 = "00"
	if _, err := VerifyChain(genesis, events, keys, keys, nil, nil); err == nil {
		t.Fatal("a first epoch naming a previous checkpoint verified")
	}
}
