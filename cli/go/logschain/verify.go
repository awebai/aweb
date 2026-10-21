package logschain

import (
	"sort"

	"github.com/awebai/aw/hookevent"
)

// Content is an event's retained content, and the producer key ingest
// verified it against.
type Content struct {
	Salt           []byte
	SigningBytes   []byte
	Signature      string
	ProducerDIDKey string
}

// StoredEvent is one stored event: its skeleton and hash, and its content
// unless purged. PurgeAct names the act that purged it, an opaque reference.
type StoredEvent struct {
	Link      Link
	EventHash string
	Content   *Content
	PurgeAct  string
}

// Artefact is a receipt's or checkpoint's signing bytes and signature.
type Artefact struct {
	SigningBytes []byte
	Signature    string
}

// Break is the first event that fails, and why.
type Break struct {
	TeamSeq int64
	Reason  string
}

// PurgedRange is an inclusive range of purged events and the act that purged them.
type PurgedRange struct {
	First, Last int64
	Act         string
}

// Contradiction is a receipt or checkpoint the chain contradicts.
type Contradiction struct {
	Artefact string
	Index    int
	Reason   string
}

// Report is what verify finds in one team epoch.
type Report struct {
	FirstBreak   *Break
	Missing      [][2]int64
	Purged       []PurgedRange
	Contradicted []Contradiction
}

// Intact is true when nothing broke, nothing is missing and no artefact is
// contradicted. A purged event does not make the chain broken.
func (r Report) Intact() bool {
	return r.FirstBreak == nil && len(r.Missing) == 0 && len(r.Contradicted) == 0
}

// JSON is the report in the vector's shape.
func (r Report) JSON() map[string]any {
	missing := make([]any, 0, len(r.Missing))
	for _, gap := range r.Missing {
		missing = append(missing, []any{gap[0], gap[1]})
	}
	purged := make([]any, 0, len(r.Purged))
	for _, p := range r.Purged {
		purged = append(purged, map[string]any{"from": p.First, "to": p.Last, "act": p.Act})
	}
	contradicted := make([]any, 0, len(r.Contradicted))
	for _, c := range r.Contradicted {
		contradicted = append(contradicted, map[string]any{"artefact": c.Artefact, "index": c.Index, "reason": c.Reason})
	}
	report := map[string]any{
		"intact": r.Intact(), "missing": missing, "purged": purged, "contradicted": contradicted,
	}
	if r.FirstBreak != nil {
		report["first_break"] = map[string]any{"team_seq": r.FirstBreak.TeamSeq, "reason": r.FirstBreak.Reason}
	}
	return report
}

// VerifyChain recomputes a team epoch's chain from its genesis and checks each
// receipt and checkpoint against it. receiptKeys and checkpointKeys are the
// did:keys the logs manifest declares for each purpose. A genesis that does
// not hold is refused: it anchors nothing.
func VerifyChain(
	genesis Genesis,
	events []StoredEvent,
	receiptKeys, checkpointKeys map[string]bool,
	receipts, checkpoints []Artefact,
) (Report, error) {
	var report Report
	genesisHash, err := genesis.Hash()
	if err != nil {
		return report, err
	}
	hashes := map[int64]string{0: genesisHash}
	stored := map[int64]StoredEvent{}
	prevHash := genesisHash
	expected := int64(1)

	ordered := append([]StoredEvent{}, events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Link.TeamSeq < ordered[j].Link.TeamSeq })
	fail := func(seq int64, reason string) {
		if report.FirstBreak == nil {
			report.FirstBreak = &Break{TeamSeq: seq, Reason: reason}
		}
	}

	for _, event := range ordered {
		seq := event.Link.TeamSeq
		if _, seen := hashes[seq]; seen {
			fail(seq, "sequence_duplicate")
			continue
		}
		linked := true
		if seq > expected {
			report.Missing = append(report.Missing, [2]int64{expected, seq - 1})
		} else {
			linked = event.Link.PrevEventHash == prevHash
		}
		if reason := eventFault(genesis, event, linked); reason != "" {
			fail(seq, reason)
		}
		if event.Content == nil && event.PurgeAct != "" {
			report.Purged = extendPurged(report.Purged, seq, event.PurgeAct)
		}
		hashes[seq] = event.EventHash
		stored[seq] = event
		prevHash = event.EventHash
		expected = seq + 1
	}

	for index, artefact := range receipts {
		if reason := receiptContradiction(artefact, receiptKeys, genesis, hashes, stored); reason != "" {
			report.Contradicted = append(report.Contradicted, Contradiction{"receipt", index, reason})
		}
	}
	for index, artefact := range checkpoints {
		if reason := checkpointContradiction(artefact, checkpointKeys, genesis, hashes); reason != "" {
			report.Contradicted = append(report.Contradicted, Contradiction{"checkpoint", index, reason})
		}
	}
	return report, nil
}

// eventFault is the first fault of one stored event, in the contract's order.
func eventFault(genesis Genesis, event StoredEvent, linked bool) string {
	link := event.Link
	if link.TeamID != genesis.TeamID || link.ChainEpoch != genesis.ChainEpoch {
		return "wrong_chain"
	}
	if !linked {
		return "prev_hash_mismatch"
	}
	if hash, err := link.EventHash(); err != nil || hash != event.EventHash {
		return "event_hash_mismatch"
	}
	content := event.Content
	if content == nil {
		if event.PurgeAct != "" {
			return ""
		}
		return "content_missing"
	}
	commitment, err := ContentCommitment(content.Salt, content.SigningBytes, content.Signature)
	if err != nil || commitment != link.ContentCommitment {
		return "commitment_mismatch"
	}
	envelope, err := hookevent.Verify(content.SigningBytes, content.Signature, hookevent.VerifyOptions{TeamID: genesis.TeamID})
	if err != nil || envelope.ProducerDIDKey != content.ProducerDIDKey {
		return "provenance_invalid"
	}
	if envelope.Hook != link.Hook || ProducerOrigin(envelope) != link.ProducerOrigin {
		return "skeleton_mismatch"
	}
	return ""
}

func extendPurged(purged []PurgedRange, seq int64, act string) []PurgedRange {
	if n := len(purged); n > 0 && purged[n-1].Act == act && purged[n-1].Last == seq-1 {
		purged[n-1].Last = seq
		return purged
	}
	return append(purged, PurgedRange{First: seq, Last: seq, Act: act})
}

// chainContradiction is why the chain contradicts an artefact naming these
// facts, in the contract's order after its signature, or "".
func chainContradiction(
	didKey string, keys map[string]bool, teamID string, epoch int64, origin string, seq int64, eventHash string,
	genesis Genesis, hashes map[int64]string,
) string {
	if !keys[didKey] {
		return "signature_invalid"
	}
	if teamID != genesis.TeamID || epoch != genesis.ChainEpoch || origin != genesis.LogsOrigin {
		return "wrong_chain"
	}
	stored, present := hashes[seq]
	if !present {
		return "not_in_chain"
	}
	if stored != eventHash {
		return "hash_mismatch"
	}
	return ""
}

func receiptContradiction(
	artefact Artefact, keys map[string]bool, genesis Genesis, hashes map[int64]string, stored map[int64]StoredEvent,
) string {
	receipt, err := OpenReceipt(artefact.SigningBytes, artefact.Signature)
	if err != nil {
		return "signature_invalid"
	}
	if reason := chainContradiction(receipt.DIDKey, keys, receipt.TeamID, receipt.ChainEpoch, receipt.LogsOrigin,
		receipt.TeamSeq, receipt.EventHash, genesis, hashes); reason != "" {
		return reason
	}
	if !receiptNamesEvent(receipt, stored[receipt.TeamSeq]) {
		return "event_mismatch"
	}
	return ""
}

// receiptNamesEvent is whether a receipt names the event stored at its
// sequence: its receipt time always, and its event id while the content is
// retained. A stored envelope that does not open names no event.
func receiptNamesEvent(receipt *Receipt, event StoredEvent) bool {
	if receipt.ReceivedAt != event.Link.ReceivedAt {
		return false
	}
	if event.Content == nil {
		return true
	}
	envelope, err := hookevent.Open(event.Content.SigningBytes)
	if err != nil {
		return false
	}
	return envelope.EventID == receipt.EventID
}

func checkpointContradiction(artefact Artefact, keys map[string]bool, genesis Genesis, hashes map[int64]string) string {
	checkpoint, err := OpenCheckpoint(artefact.SigningBytes, artefact.Signature)
	if err != nil {
		return "signature_invalid"
	}
	return chainContradiction(checkpoint.DIDKey, keys, checkpoint.TeamID, checkpoint.ChainEpoch, checkpoint.LogsOrigin,
		checkpoint.TeamSeq, checkpoint.EventHash, genesis, hashes)
}
