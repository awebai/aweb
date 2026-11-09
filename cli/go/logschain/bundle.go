package logschain

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/awebai/aw/strictjson"
)

// exportType is the header type of a team's exported log, aweb.logs-export/1.
const exportType = "aweb.logs-export"

// MaxLineBytes is the longest line a bundle holds, its newline excluded. An
// event line carries at most one hook envelope (hookevent.MaxEnvelopeBytes, 256 KiB),
// base64url-encoded, beside its link and key evidence; this leaves room for
// those and refuses a line no exporter writes before a verifier holds it whole.
const MaxLineBytes = 1 << 20

// BundleMalformed is a bundle that is not a well-formed export. Line counts
// from 1.
type BundleMalformed struct {
	Line   int
	Reason string
}

func (e *BundleMalformed) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Reason)
}

// EpochReport is one epoch of a bundle: its chain report, whether it links to
// its predecessor, and how far the bundle's checkpoints reach in it.
type EpochReport struct {
	ChainEpoch int64
	Chain      Report
	Linked     bool
	// AnchoredTo is the highest team_seq a checkpoint that holds witnesses;
	// Anchored is false when none does.
	AnchoredTo int64
	Anchored   bool
	// Unanchored is the inclusive range of events after AnchoredTo; nil when
	// there are none.
	Unanchored *[2]int64
}

// LastCheckpoint names the last checkpoint of a bundle that holds.
type LastCheckpoint struct {
	ChainEpoch         int64
	TeamSeq            int64
	SigningBytesSHA256 string
}

// BundleReport is what a bundle proves, and how far.
type BundleReport struct {
	ReceiptKeys           []string
	CheckpointKeys        []string
	Epochs                []EpochReport
	LastCheckpoint        *LastCheckpoint
	WitnessesContradicted []Contradiction
}

// Intact is true when every epoch is intact and linked and no witness is
// contradicted. Unanchored events never break it.
func (r BundleReport) Intact() bool {
	for _, epoch := range r.Epochs {
		if !epoch.Chain.Intact() || !epoch.Linked {
			return false
		}
	}
	return len(r.WitnessesContradicted) == 0
}

// JSON is the report in the vector's shape.
func (r BundleReport) JSON() map[string]any {
	epochs := make([]any, 0, len(r.Epochs))
	for _, epoch := range r.Epochs {
		report := epoch.Chain.JSON()
		report["chain_epoch"] = epoch.ChainEpoch
		report["linked"] = epoch.Linked
		if epoch.Anchored {
			report["anchored_to"] = epoch.AnchoredTo
		}
		if epoch.Unanchored != nil {
			report["unanchored"] = []any{epoch.Unanchored[0], epoch.Unanchored[1]}
		}
		epochs = append(epochs, report)
	}
	contradicted := make([]any, 0, len(r.WitnessesContradicted))
	for _, c := range r.WitnessesContradicted {
		contradicted = append(contradicted, map[string]any{"artefact": c.Artefact, "index": c.Index, "reason": c.Reason})
	}
	report := map[string]any{
		"intact":        r.Intact(),
		"accepted_keys": map[string]any{"receipt": sortedKeys(r.ReceiptKeys), "checkpoint": sortedKeys(r.CheckpointKeys)},
		"epochs":        epochs,
		"witnesses":     map[string]any{"contradicted": contradicted},
	}
	if r.LastCheckpoint != nil {
		report["last_checkpoint"] = map[string]any{
			"chain_epoch":          r.LastCheckpoint.ChainEpoch,
			"team_seq":             r.LastCheckpoint.TeamSeq,
			"signing_bytes_sha256": r.LastCheckpoint.SigningBytesSHA256,
		}
	}
	return report
}

func sortedKeys(keys []string) []any {
	sorted := append([]string{}, keys...)
	sort.Strings(sorted)
	out := make([]any, 0, len(sorted))
	for _, key := range sorted {
		out = append(out, key)
	}
	return out
}

type witness struct {
	kind     string
	index    int
	artefact Artefact
	teamID   string
	epoch    int64
	teamSeq  int64
}

type storedPosition struct {
	hash  string
	event StoredEvent
}

// bundleEpoch is one epoch's pass over a bundle: the chain state, the
// position the next artefact witnesses, and the coverage so far.
type bundleEpoch struct {
	state           *epochState
	linked          bool
	witnessed       map[int64]bool
	positionSeq     int64
	positionHash    string
	positionEvent   *StoredEvent
	counts          map[string]int
	anchored        bool
	anchoredTo      int64
	firstUnanchored int64
	lastSeq         int64
	// Checkpoints that hold at the current position; at the end, the epoch's
	// head checkpoints.
	headCheckpoints map[string]bool
	positions       map[int64]storedPosition
}

func newBundleEpoch(genesis Genesis, linked bool, witnessed map[int64]bool) (*bundleEpoch, error) {
	state, err := newEpochState(genesis)
	if err != nil {
		return nil, err
	}
	return &bundleEpoch{
		state: state, linked: linked, witnessed: witnessed, positionHash: state.genesisHash,
		counts: map[string]int{}, headCheckpoints: map[string]bool{}, positions: map[int64]storedPosition{},
	}, nil
}

func (e *bundleEpoch) event(event StoredEvent) {
	seq := event.Link.TeamSeq
	if e.lastSeq != 0 && seq == e.lastSeq {
		e.state.fail(seq, "sequence_duplicate")
		return
	}
	if seq < e.lastSeq {
		e.state.fail(seq, "misplaced")
		return
	}
	e.state.add(event)
	e.positionSeq, e.positionHash, e.positionEvent = seq, event.EventHash, &event
	e.lastSeq = seq
	e.headCheckpoints = map[string]bool{}
	if e.firstUnanchored == 0 {
		e.firstUnanchored = seq
	}
	if e.witnessed[seq] {
		e.positions[seq] = storedPosition{hash: event.EventHash, event: event}
	}
}

// artefact checks one of the bundle's artefacts at the current position, and
// says whether it holds.
func (e *bundleEpoch) artefact(kind string, artefact Artefact, keys map[string]bool) bool {
	index := e.counts[kind]
	e.counts[kind]++
	opened, reason := acceptedArtefact(kind, artefact, keys, e.state.genesis)
	if opened != nil {
		if opened.teamSeq != e.positionSeq {
			reason = "misplaced"
		} else {
			reason = opened.atPosition(e.positionHash, e.positionEvent)
		}
	}
	if reason != "" {
		e.state.report.Contradicted = append(e.state.report.Contradicted, Contradiction{kind, index, reason})
		return false
	}
	if kind == "checkpoint" {
		e.anchored, e.anchoredTo, e.firstUnanchored = true, e.positionSeq, 0
		e.headCheckpoints[ArtefactSHA256(artefact.SigningBytes)] = true
	}
	return true
}

func (e *bundleEpoch) witnessFault(w witness, keys map[string]bool) string {
	opened, reason := acceptedArtefact(w.kind, w.artefact, keys, e.state.genesis)
	if opened == nil {
		return reason
	}
	if opened.teamSeq == 0 {
		return opened.atPosition(e.state.genesisHash, nil)
	}
	stored, present := e.positions[opened.teamSeq]
	if !present {
		return "not_in_chain"
	}
	return opened.atPosition(stored.hash, &stored.event)
}

func (e *bundleEpoch) report() EpochReport {
	report := EpochReport{
		ChainEpoch: e.state.genesis.ChainEpoch, Chain: e.state.report, Linked: e.linked,
		Anchored: e.anchored, AnchoredTo: e.anchoredTo,
	}
	if e.firstUnanchored != 0 {
		report.Unanchored = &[2]int64{e.firstUnanchored, e.lastSeq}
	}
	return report
}

// VerifyBundle verifies a team's exported log, read line by line, against the
// receipt and checkpoint keys the verifier accepts and the witnesses it holds
// independently of the exporter. A bundle that is not one is refused with a
// *BundleMalformed.
func VerifyBundle(
	r io.Reader,
	receiptKeys, checkpointKeys map[string]bool,
	witnessReceipts, witnessCheckpoints []Artefact,
) (BundleReport, error) {
	keys := map[string]map[string]bool{"receipt": receiptKeys, "checkpoint": checkpointKeys}
	report := BundleReport{ReceiptKeys: keyList(receiptKeys), CheckpointKeys: keyList(checkpointKeys)}
	held := map[[2]any]string{}
	var witnesses []witness
	for _, given := range []struct {
		kind      string
		artefacts []Artefact
	}{{"receipt", witnessReceipts}, {"checkpoint", witnessCheckpoints}} {
		for index, artefact := range given.artefacts {
			w := witness{kind: given.kind, index: index, artefact: artefact}
			if given.kind == "receipt" {
				receipt, err := OpenReceipt(artefact.SigningBytes, artefact.Signature)
				if err != nil || !receiptKeys[receipt.DIDKey] {
					held[[2]any{given.kind, index}] = "signature_invalid"
					continue
				}
				w.teamID, w.epoch, w.teamSeq = receipt.TeamID, receipt.ChainEpoch, receipt.TeamSeq
			} else {
				checkpoint, err := OpenCheckpoint(artefact.SigningBytes, artefact.Signature)
				if err != nil || !checkpointKeys[checkpoint.DIDKey] {
					held[[2]any{given.kind, index}] = "signature_invalid"
					continue
				}
				w.teamID, w.epoch, w.teamSeq = checkpoint.TeamID, checkpoint.ChainEpoch, checkpoint.TeamSeq
			}
			witnesses = append(witnesses, w)
		}
	}

	var current *bundleEpoch
	present := map[int64]bool{}
	closeEpoch := func(epoch *bundleEpoch) {
		report.Epochs = append(report.Epochs, epoch.report())
		present[epoch.state.genesis.ChainEpoch] = true
		for _, w := range witnesses {
			if w.epoch != epoch.state.genesis.ChainEpoch {
				continue
			}
			if _, done := held[[2]any{w.kind, w.index}]; done {
				continue
			}
			if reason := epoch.witnessFault(w, keys[w.kind]); reason != "" {
				held[[2]any{w.kind, w.index}] = reason
			}
		}
	}

	// A line and its newline fit the buffer, so a longer one is refused
	// before it is read whole.
	reader := bufio.NewReaderSize(r, MaxLineBytes+1)
	teamID := ""
	number := 0
	for {
		slice, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) && len(slice) == 0 {
			break
		}
		number++
		if errors.Is(err, bufio.ErrBufferFull) {
			return report, &BundleMalformed{number, fmt.Sprintf("a line is at most %d bytes", MaxLineBytes)}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return report, err
		}
		raw := bytes.Clone(slice)
		if !bytes.HasSuffix(raw, []byte("\n")) {
			return report, &BundleMalformed{number, "a line ends with a newline"}
		}
		record, perr := strictjson.ParseCanonicalObject(raw[:len(raw)-1])
		if perr != nil {
			return report, &BundleMalformed{number, "not a strict canonical JSON object: " + perr.Error()}
		}
		if teamID == "" {
			if teamID, err = bundleHeader(record, number); err != nil {
				return report, err
			}
			for _, w := range witnesses {
				if w.teamID != teamID {
					held[[2]any{w.kind, w.index}] = "wrong_chain"
				}
			}
			continue
		}
		name, value, err := bundleRecord(record, number)
		if err != nil {
			return report, err
		}
		switch name {
		case "genesis":
			genesis, err := bundleGenesis(value, number)
			if err != nil {
				return report, err
			}
			linked := genesis.ChainEpoch == 1
			if current != nil {
				previous := current.state.genesis.ChainEpoch
				if genesis.ChainEpoch <= previous {
					return report, &BundleMalformed{number, "epochs are not in increasing order"}
				}
				closeEpoch(current)
				linked = genesis.ChainEpoch == previous+1 && current.headCheckpoints[genesis.PreviousCheckpointSHA256]
			}
			linked = linked && genesis.TeamID == teamID
			witnessed := map[int64]bool{}
			for _, w := range witnesses {
				if w.epoch == genesis.ChainEpoch {
					witnessed[w.teamSeq] = true
				}
			}
			if current, err = newBundleEpoch(genesis, linked, witnessed); err != nil {
				return report, &BundleMalformed{number, "genesis: " + err.Error()}
			}
		case "event":
			if current == nil {
				return report, &BundleMalformed{number, "an event record precedes its epoch's genesis"}
			}
			event, err := bundleEvent(value, number)
			if err != nil {
				return report, err
			}
			current.event(event)
		default:
			if current == nil {
				return report, &BundleMalformed{number, "a " + name + " record precedes its epoch's genesis"}
			}
			artefact, err := bundleArtefact(value, number)
			if err != nil {
				return report, err
			}
			if current.artefact(name, artefact, keys[name]) && name == "checkpoint" {
				report.LastCheckpoint = &LastCheckpoint{
					ChainEpoch: current.state.genesis.ChainEpoch, TeamSeq: current.positionSeq,
					SigningBytesSHA256: ArtefactSHA256(artefact.SigningBytes),
				}
			}
		}
	}
	if teamID == "" {
		return report, &BundleMalformed{number + 1, "the bundle has no header"}
	}
	if current != nil {
		closeEpoch(current)
	}
	for _, w := range witnesses {
		key := [2]any{w.kind, w.index}
		if _, done := held[key]; !done && !present[w.epoch] {
			held[key] = "epoch_absent"
		}
	}
	for key, reason := range held {
		report.WitnessesContradicted = append(report.WitnessesContradicted, Contradiction{key[0].(string), key[1].(int), reason})
	}
	sort.Slice(report.WitnessesContradicted, func(i, j int) bool {
		a, b := report.WitnessesContradicted[i], report.WitnessesContradicted[j]
		if a.Artefact != b.Artefact {
			return a.Artefact == "receipt"
		}
		return a.Index < b.Index
	})
	return report, nil
}

func keyList(keys map[string]bool) []string {
	list := make([]string, 0, len(keys))
	for key := range keys {
		list = append(list, key)
	}
	return list
}

func bundleHeader(record map[string]any, number int) (string, error) {
	teamID, ok := record["team_id"].(string)
	if len(record) != 3 || record["v"] != int64(1) || record["type"] != exportType || !ok {
		return "", &BundleMalformed{number, "the first line is the " + exportType + " v1 header"}
	}
	return teamID, nil
}

func bundleRecord(record map[string]any, number int) (string, map[string]any, error) {
	if len(record) == 1 {
		for name, value := range record {
			switch name {
			case "genesis", "event", "receipt", "checkpoint":
				if object, ok := value.(map[string]any); ok {
					return name, object, nil
				}
			}
		}
	}
	return "", nil, &BundleMalformed{number, "not a genesis, event, receipt or checkpoint record"}
}

// fieldsOf checks that object holds every required field and no field but
// those and the optional ones.
func fieldsOf(object any, number int, required, optional []string) (map[string]any, error) {
	fields, ok := object.(map[string]any)
	if !ok {
		return nil, &BundleMalformed{number, "the record's fields"}
	}
	allowed := map[string]bool{}
	for _, name := range append(append([]string{}, required...), optional...) {
		allowed[name] = true
	}
	for _, name := range required {
		if _, present := fields[name]; !present {
			return nil, &BundleMalformed{number, "the record's fields"}
		}
	}
	for name := range fields {
		if !allowed[name] {
			return nil, &BundleMalformed{number, "the record's fields"}
		}
	}
	return fields, nil
}

func bundleGenesis(value map[string]any, number int) (Genesis, error) {
	fields, err := fieldsOf(value, number,
		[]string{"team_id", "chain_epoch", "logs_origin", "created_at"}, []string{"previous_checkpoint_sha256"})
	if err != nil {
		return Genesis{}, err
	}
	// The genesis is exactly as hashed: a present optional field is a non-empty
	// string, never read as absent.
	if raw, present := fields["previous_checkpoint_sha256"]; present {
		if value, ok := raw.(string); !ok || value == "" {
			return Genesis{}, &BundleMalformed{number, "genesis: previous_checkpoint_sha256"}
		}
	}
	genesis := Genesis{
		TeamID: text(fields, "team_id"), ChainEpoch: integer(fields, "chain_epoch"),
		LogsOrigin: text(fields, "logs_origin"), CreatedAt: text(fields, "created_at"),
		PreviousCheckpointSHA256: text(fields, "previous_checkpoint_sha256"),
	}
	if _, err := genesis.fields(); err != nil {
		return Genesis{}, &BundleMalformed{number, "genesis: " + err.Error()}
	}
	return genesis, nil
}

func bundleEvent(value map[string]any, number int) (StoredEvent, error) {
	stored, err := fieldsOf(value, number, []string{"link", "event_hash", "key_evidence"}, []string{"content", "purge_act"})
	if err != nil {
		return StoredEvent{}, err
	}
	link, err := fieldsOf(stored["link"], number, []string{
		"chain_epoch", "team_id", "team_seq", "prev_event_hash", "received_at", "hook", "producer_origin",
		"content_commitment",
	}, nil)
	if err != nil {
		return StoredEvent{}, err
	}
	names := make([]string, 0, len(link))
	for name := range link {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := link[name]
		var ok bool
		if name == "chain_epoch" || name == "team_seq" {
			_, ok = value.(int64)
		} else {
			_, ok = value.(string)
		}
		if !ok {
			return StoredEvent{}, &BundleMalformed{number, "link " + name}
		}
	}
	evidence, err := fieldsOf(stored["key_evidence"], number,
		[]string{"kid", "did_key", "purposes"}, []string{"installation_id", "generation", "binding_ids"})
	if err != nil {
		return StoredEvent{}, err
	}
	if !evidenceTyped(evidence) {
		return StoredEvent{}, &BundleMalformed{number, "key_evidence"}
	}
	eventHash, ok := stored["event_hash"].(string)
	if !ok {
		return StoredEvent{}, &BundleMalformed{number, "event_hash"}
	}
	event := StoredEvent{
		Link: Link{
			ChainEpoch: integer(link, "chain_epoch"), TeamID: text(link, "team_id"), TeamSeq: integer(link, "team_seq"),
			PrevEventHash: text(link, "prev_event_hash"), ReceivedAt: text(link, "received_at"), Hook: text(link, "hook"),
			ProducerOrigin: text(link, "producer_origin"), ContentCommitment: text(link, "content_commitment"),
		},
		EventHash: eventHash,
	}
	if raw, present := stored["content"]; present {
		parts, err := fieldsOf(raw, number, []string{"salt", "signing_bytes", "signature"}, nil)
		if err != nil {
			return StoredEvent{}, err
		}
		salt, serr := decodeText(parts, "salt")
		signing, berr := decodeText(parts, "signing_bytes")
		signature, sok := parts["signature"].(string)
		if serr != nil || berr != nil || !sok {
			return StoredEvent{}, &BundleMalformed{number, "content"}
		}
		event.Content = &Content{Salt: salt, SigningBytes: signing, Signature: signature, ProducerDIDKey: text(evidence, "did_key")}
	}
	if raw, present := stored["purge_act"]; present {
		act, ok := raw.(string)
		if !ok || act == "" {
			return StoredEvent{}, &BundleMalformed{number, "purge_act"}
		}
		event.PurgeAct = act
	}
	return event, nil
}

func evidenceTyped(evidence map[string]any) bool {
	for _, name := range []string{"kid", "did_key", "installation_id"} {
		if value, present := evidence[name]; present {
			if _, ok := value.(string); !ok {
				return false
			}
		}
	}
	for _, name := range []string{"purposes", "binding_ids"} {
		if value, present := evidence[name]; present {
			items, ok := value.([]any)
			if !ok {
				return false
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return false
				}
			}
		}
	}
	if value, present := evidence["generation"]; present {
		if _, ok := value.(int64); !ok {
			return false
		}
	}
	return true
}

func decodeText(fields map[string]any, name string) ([]byte, error) {
	value, ok := fields[name].(string)
	if !ok {
		return nil, errors.New(name)
	}
	return strictjson.DecodeBase64URL(value, name)
}

func bundleArtefact(value map[string]any, number int) (Artefact, error) {
	parts, err := fieldsOf(value, number, []string{"signing_bytes", "signature"}, nil)
	if err != nil {
		return Artefact{}, err
	}
	signing, derr := decodeText(parts, "signing_bytes")
	signature, ok := parts["signature"].(string)
	if derr != nil || !ok {
		return Artefact{}, &BundleMalformed{number, "artefact"}
	}
	return Artefact{SigningBytes: signing, Signature: signature}, nil
}
