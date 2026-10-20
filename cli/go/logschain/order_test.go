package logschain

import (
	"testing"
)

// The vector pins most of verify's normative break order. These cases pin the
// precedences no vector case combines, on the vector's own intact chain.

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

func rehash(t *testing.T, event *StoredEvent) {
	t.Helper()
	hash, err := event.Link.EventHash()
	if err != nil {
		t.Fatal(err)
	}
	event.EventHash = hash
}

func firstBreak(t *testing.T, genesis Genesis, events []StoredEvent, keys map[string]bool) *Break {
	t.Helper()
	report, err := VerifyChain(genesis, events, keys, keys, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return report.FirstBreak
}

func TestADuplicateSequenceComesBeforeEveryOtherFault(t *testing.T) {
	genesis, events, keys := intactCase(t)
	duplicate := events[1]
	duplicate.Link.TeamID = "other:example.com"
	events = append(events, duplicate)
	if got := firstBreak(t, genesis, events, keys); got == nil || *got != (Break{2, "sequence_duplicate"}) {
		t.Fatalf("first break %+v", got)
	}
}

func TestWrongChainComesBeforeABrokenLink(t *testing.T) {
	genesis, events, keys := intactCase(t)
	events[1].Link.TeamID = "other:example.com"
	events[1].Link.PrevEventHash = events[2].EventHash
	if got := firstBreak(t, genesis, events, keys); got == nil || *got != (Break{2, "wrong_chain"}) {
		t.Fatalf("first break %+v", got)
	}
}

func TestAWrongEventHashComesBeforeMissingContent(t *testing.T) {
	genesis, events, keys := intactCase(t)
	events[2].Content = nil
	events[2].EventHash = events[1].EventHash
	if got := firstBreak(t, genesis, events, keys); got == nil || *got != (Break{3, "event_hash_mismatch"}) {
		t.Fatalf("first break %+v", got)
	}
}

func TestProvenanceComesBeforeTheSkeleton(t *testing.T) {
	genesis, events, keys := intactCase(t)
	// Another producer key and another hook in the skeleton, rehashed: the
	// commitment still holds, the key evidence fails first.
	events[0].Content.ProducerDIDKey = events[1].Content.ProducerDIDKey
	events[0].Link.Hook = "post-governance-hook"
	rehash(t, &events[0])
	if got := firstBreak(t, genesis, events, keys); got == nil || *got != (Break{1, "provenance_invalid"}) {
		t.Fatalf("first break %+v", got)
	}
}

func TestASkeletonThatDisagreesWithItsEnvelopeBreaks(t *testing.T) {
	genesis, events, keys := intactCase(t)
	events[0].Link.Hook = "post-governance-hook"
	rehash(t, &events[0])
	if got := firstBreak(t, genesis, events, keys); got == nil || *got != (Break{1, "skeleton_mismatch"}) {
		t.Fatalf("first break %+v", got)
	}
}

func TestAGenesisThatDoesNotHoldIsRefused(t *testing.T) {
	genesis, events, keys := intactCase(t)
	genesis.PreviousCheckpointSHA256 = "00"
	if _, err := VerifyChain(genesis, events, keys, keys, nil, nil); err == nil {
		t.Fatal("a first epoch naming a previous checkpoint verified")
	}
}
