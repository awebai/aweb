package logschain

import (
	"sort"

	"github.com/awebai/aw/hookevent"
)

// logRecordKind is the closed vocabulary in docs/logs-chain.md, “The bundle,” lines 269–277.
type logRecordKind string

const (
	genesisRecord    logRecordKind = "genesis"
	eventRecord      logRecordKind = "event"
	receiptRecord    logRecordKind = "receipt"
	checkpointRecord logRecordKind = "checkpoint"
)

// chainFault is the ordered verification vocabulary in docs/logs-chain.md, “Verifying a chain,” lines 150–180.
type chainFault string

const (
	noChainFault           chainFault = ""
	sequenceDuplicateFault chainFault = "sequence_duplicate"
	misplacedFault         chainFault = "misplaced"
	wrongChainFault        chainFault = "wrong_chain"
	previousHashFault      chainFault = "prev_hash_mismatch"
	eventHashFault         chainFault = "event_hash_mismatch"
	contentMissingFault    chainFault = "content_missing"
	commitmentFault        chainFault = "commitment_mismatch"
	provenanceFault        chainFault = "provenance_invalid"
	skeletonFault          chainFault = "skeleton_mismatch"
	signatureFault         chainFault = "signature_invalid"
	notInChainFault        chainFault = "not_in_chain"
	hashMismatchFault      chainFault = "hash_mismatch"
	eventMismatchFault     chainFault = "event_mismatch"
	epochAbsentFault       chainFault = "epoch_absent"
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
	// The compatibility API takes unordered epoch data. Sort it at this input
	// boundary; the export reader intentionally preserves and checks wire order.
	positions := map[int64]bool{}
	for _, event := range events {
		positions[event.Link.TeamSeq] = true
	}
	epoch, err := newBundleEpoch(epochVerificationOptions{Genesis: genesis, LinkedToPredecessor: true, WitnessedPositions: positions})
	if err != nil {
		return Report{}, err
	}
	ordered := append([]StoredEvent{}, events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Link.TeamSeq < ordered[j].Link.TeamSeq })
	for _, event := range ordered {
		epoch.event(event)
	}
	for _, given := range []struct {
		kind   logRecordKind
		values []Artefact
		keys   map[string]bool
	}{
		{receiptRecord, receipts, receiptKeys}, {checkpointRecord, checkpoints, checkpointKeys},
	} {
		for index, artefact := range given.values {
			if reason := epoch.witnessFault(witness{kind: given.kind, artefact: artefact}, given.keys); reason != noChainFault {
				epoch.state.report.Contradicted = append(epoch.state.report.Contradicted, Contradiction{string(given.kind), index, string(reason)})
			}
		}
	}
	return epoch.state.report, nil
}

// epochState is the running check of one epoch's events, taken in increasing
// team_seq order: the chain links, sequence gaps, purged ranges and the first
// break.
type epochState struct {
	genesis     Genesis
	genesisHash string
	report      Report
	prevHash    string
	expected    int64
}

func newEpochState(genesis Genesis) (*epochState, error) {
	hash, err := genesis.Hash()
	if err != nil {
		return nil, err
	}
	return &epochState{genesis: genesis, genesisHash: hash, prevHash: hash, expected: 1}, nil
}

func (s *epochState) fail(seq int64, reason chainFault) {
	if s.report.FirstBreak == nil {
		s.report.FirstBreak = &Break{TeamSeq: seq, Reason: string(reason)}
	}
}

// add checks the next event, whose team_seq is greater than any before it.
func (s *epochState) add(event StoredEvent) {
	seq := event.Link.TeamSeq
	linked := true
	if seq > s.expected {
		s.report.Missing = append(s.report.Missing, [2]int64{s.expected, seq - 1})
	} else {
		linked = event.Link.PrevEventHash == s.prevHash
	}
	if reason := (eventVerification{Genesis: s.genesis, Event: event, LinkedToPrevious: linked}).fault(); reason != noChainFault {
		s.fail(seq, reason)
	}
	if event.Content == nil && event.PurgeAct != "" {
		s.report.Purged = extendPurged(s.report.Purged, seq, event.PurgeAct)
	}
	s.prevHash = event.EventHash
	s.expected = seq + 1
}

// eventVerification checks one stored event in the fault order of
// docs/logs-chain.md, “Verifying a chain,” lines 150–164.
type eventVerification struct {
	Genesis          Genesis
	Event            StoredEvent
	LinkedToPrevious bool
}

func (verification eventVerification) fault() chainFault {
	genesis, event, linked := verification.Genesis, verification.Event, verification.LinkedToPrevious
	link := event.Link
	if link.TeamID != genesis.TeamID || link.ChainEpoch != genesis.ChainEpoch {
		return wrongChainFault
	}
	if !linked {
		return previousHashFault
	}
	if hash, err := link.EventHash(); err != nil || hash != event.EventHash {
		return eventHashFault
	}
	content := event.Content
	if content == nil {
		if event.PurgeAct != "" {
			return noChainFault
		}
		return contentMissingFault
	}
	commitment, err := ContentCommitment(content.Salt, content.SigningBytes, content.Signature)
	if err != nil || commitment != link.ContentCommitment {
		return commitmentFault
	}
	envelope, err := hookevent.Verify(content.SigningBytes, content.Signature, hookevent.VerifyOptions{TeamID: genesis.TeamID})
	if err != nil || envelope.ProducerDIDKey != content.ProducerDIDKey {
		return provenanceFault
	}
	if envelope.Hook != link.Hook || ProducerOrigin(envelope) != link.ProducerOrigin {
		return skeletonFault
	}
	return noChainFault
}

func extendPurged(purged []PurgedRange, seq int64, act string) []PurgedRange {
	if n := len(purged); n > 0 && purged[n-1].Act == act && purged[n-1].Last == seq-1 {
		purged[n-1].Last = seq
		return purged
	}
	return append(purged, PurgedRange{First: seq, Last: seq, Act: act})
}

// openedArtefact is a receipt or checkpoint opened under an accepted key for
// an epoch: the facts the chain is checked against.
type openedArtefact struct {
	teamSeq   int64
	eventHash string
	receipt   *Receipt
}

// acceptedArtefact opens a receipt or checkpoint signed by one of keys for this
// epoch, or says why it is contradicted before its position is looked at.
func acceptedArtefact(kind logRecordKind, artefact Artefact, keys map[string]bool, genesis Genesis) (*openedArtefact, chainFault) {
	var didKey, teamID, origin string
	var epoch int64
	opened := &openedArtefact{}
	if kind == receiptRecord {
		receipt, err := OpenReceipt(artefact.SigningBytes, artefact.Signature)
		if err != nil {
			return nil, signatureFault
		}
		didKey, teamID, epoch, origin = receipt.DIDKey, receipt.TeamID, receipt.ChainEpoch, receipt.LogsOrigin
		opened.teamSeq, opened.eventHash, opened.receipt = receipt.TeamSeq, receipt.EventHash, receipt
	} else {
		checkpoint, err := OpenCheckpoint(artefact.SigningBytes, artefact.Signature)
		if err != nil {
			return nil, signatureFault
		}
		didKey, teamID, epoch, origin = checkpoint.DIDKey, checkpoint.TeamID, checkpoint.ChainEpoch, checkpoint.LogsOrigin
		opened.teamSeq, opened.eventHash = checkpoint.TeamSeq, checkpoint.EventHash
	}
	if !keys[didKey] {
		return nil, signatureFault
	}
	if teamID != genesis.TeamID || epoch != genesis.ChainEpoch || origin != genesis.LogsOrigin {
		return nil, wrongChainFault
	}
	return opened, noChainFault
}

// atPosition is why the chain at the artefact's position, holding storedHash
// and the stored event (nil at the genesis), contradicts it, or "".
func (a *openedArtefact) atPosition(storedHash string, stored *StoredEvent) chainFault {
	if storedHash != a.eventHash {
		return hashMismatchFault
	}
	if a.receipt != nil && (stored == nil || !receiptNamesEvent(a.receipt, *stored)) {
		return eventMismatchFault
	}
	return noChainFault
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
