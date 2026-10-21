// Package logschain verifies a logs installation's hash chain and the
// receipts and checkpoints it signs, offline, from the bytes alone.
//
// docs/logs-chain.md is the contract and its vector pins the bytes; the
// Python implementation in naapp/logs regenerates the vector and this package
// passes it. Objects are strict canonical JSON under the
// hook event rules (strictjson), each behind its own domain prefix.
package logschain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/awebai/aw/hookevent"
	"github.com/awebai/aw/strictjson"
)

// The purposes a logs manifest declares for the keys that sign its artefacts.
const (
	ReceiptPurpose    = "logs-receipt"
	CheckpointPurpose = "logs-checkpoint"
)

const (
	genesisPrefix    = "aweb.logs-genesis/1\n"
	commitPrefix     = "aweb.logs-commit/1\n"
	chainPrefix      = "aweb.logs-chain/1\n"
	receiptPrefix    = "aweb.logs-receipt/1\n"
	checkpointPrefix = "aweb.logs-checkpoint/1\n"
	receiptType      = "aweb.logs-receipt"
	checkpointType   = "aweb.logs-checkpoint"
	saltBytes        = 32
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ArtefactSHA256 is the digest by which a later checkpoint or epoch names a checkpoint.
func ArtefactSHA256(signingBytes []byte) string {
	return sha256Hex(signingBytes)
}

// Genesis is the start of one team's chain epoch. PreviousCheckpointSHA256 is
// the previous epoch's final checkpoint, empty in the first epoch.
type Genesis struct {
	TeamID                   string
	ChainEpoch               int64
	LogsOrigin               string
	CreatedAt                string
	PreviousCheckpointSHA256 string
}

func (g Genesis) fields() (map[string]any, error) {
	f := map[string]any{
		"team_id":     g.TeamID,
		"chain_epoch": g.ChainEpoch,
		"logs_origin": g.LogsOrigin,
		"created_at":  g.CreatedAt,
	}
	if g.PreviousCheckpointSHA256 != "" {
		f["previous_checkpoint_sha256"] = g.PreviousCheckpointSHA256
	}
	if err := match(f, "team_id", hookevent.TeamIDPattern); err != nil {
		return nil, err
	}
	if err := counter(f, "chain_epoch", 1); err != nil {
		return nil, err
	}
	if err := match(f, "logs_origin", hookevent.OriginPattern); err != nil {
		return nil, err
	}
	if err := hookevent.ExactTime(f, "created_at", hookevent.EventTimeLayout); err != nil {
		return nil, err
	}
	if g.ChainEpoch == 1 {
		if g.PreviousCheckpointSHA256 != "" {
			return nil, strictjson.Refuse("invalid_value", "the first epoch has no previous checkpoint")
		}
	} else {
		if g.PreviousCheckpointSHA256 == "" {
			return nil, strictjson.Refuse("missing_field", "previous_checkpoint_sha256")
		}
		if err := match(f, "previous_checkpoint_sha256", digestPattern); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// Hash is the epoch's genesis hash, the previous hash of its first event.
func (g Genesis) Hash() (string, error) {
	f, err := g.fields()
	if err != nil {
		return "", err
	}
	return prefixedHash(genesisPrefix, f)
}

// ContentCommitment commits to an event's retained content: its 32-byte salt,
// its envelope signing bytes and its raw 64-byte signature.
func ContentCommitment(salt, signingBytes []byte, signature string) (string, error) {
	if len(salt) != saltBytes {
		return "", strictjson.Refuse("invalid_value", "a salt is %d bytes", saltBytes)
	}
	raw, err := strictjson.DecodeSignature(signature)
	if err != nil {
		return "", err
	}
	data := append(append(append([]byte(commitPrefix), salt...), signingBytes...), raw...)
	return sha256Hex(data), nil
}

// ProducerOrigin names an event's producer as the chain does: its origin, or
// its certificate for a client, which has no origin.
func ProducerOrigin(event *hookevent.Envelope) string {
	producer, _ := event.Fields["producer"].(map[string]any)
	if event.ProducerKind == "client" {
		certificate, _ := producer["certificate_id"].(string)
		return "client:" + certificate
	}
	origin, _ := producer["origin"].(string)
	return origin
}

// Link is an event's skeleton: what the chain hashes, and what a purge keeps.
type Link struct {
	ChainEpoch        int64
	TeamID            string
	TeamSeq           int64
	PrevEventHash     string
	ReceivedAt        string
	Hook              string
	ProducerOrigin    string
	ContentCommitment string
}

func (l Link) fields() (map[string]any, error) {
	f := map[string]any{
		"chain_epoch":        l.ChainEpoch,
		"team_id":            l.TeamID,
		"team_seq":           l.TeamSeq,
		"prev_event_hash":    l.PrevEventHash,
		"received_at":        l.ReceivedAt,
		"hook":               l.Hook,
		"producer_origin":    l.ProducerOrigin,
		"content_commitment": l.ContentCommitment,
	}
	if err := counter(f, "chain_epoch", 1); err != nil {
		return nil, err
	}
	if err := match(f, "team_id", hookevent.TeamIDPattern); err != nil {
		return nil, err
	}
	if err := counter(f, "team_seq", 1); err != nil {
		return nil, err
	}
	if err := match(f, "prev_event_hash", digestPattern); err != nil {
		return nil, err
	}
	if err := hookevent.ExactTime(f, "received_at", hookevent.EventTimeLayout); err != nil {
		return nil, err
	}
	if l.Hook == "" {
		return nil, strictjson.Refuse("invalid_value", "hook")
	}
	if l.ProducerOrigin == "" {
		return nil, strictjson.Refuse("invalid_value", "producer_origin")
	}
	if err := match(f, "content_commitment", digestPattern); err != nil {
		return nil, err
	}
	return f, nil
}

// EventHash is the hash of the link, the event's place in the chain.
func (l Link) EventHash() (string, error) {
	f, err := l.fields()
	if err != nil {
		return "", err
	}
	return prefixedHash(chainPrefix, f)
}

// Receipt is aweb.logs-receipt/1: logs' signed statement that it appended one event.
type Receipt struct {
	TeamID     string
	EventID    string
	ChainEpoch int64
	TeamSeq    int64
	EventHash  string
	ReceivedAt string
	LogsOrigin string
	KID        string
	DIDKey     string
}

// Fields is the receipt's signed object.
func (r Receipt) Fields() map[string]any {
	return map[string]any{
		"v": int64(1), "type": receiptType,
		"team_id": r.TeamID, "event_id": r.EventID, "chain_epoch": r.ChainEpoch,
		"team_seq": r.TeamSeq, "event_hash": r.EventHash, "received_at": r.ReceivedAt,
		"logs_origin": r.LogsOrigin, "kid": r.KID, "did_key": r.DIDKey,
	}
}

func (r Receipt) check() error {
	f := r.Fields()
	if err := match(f, "team_id", hookevent.TeamIDPattern); err != nil {
		return err
	}
	if err := match(f, "event_id", hookevent.UUIDPattern); err != nil {
		return err
	}
	if err := counter(f, "chain_epoch", 1); err != nil {
		return err
	}
	if err := counter(f, "team_seq", 1); err != nil {
		return err
	}
	if err := match(f, "event_hash", digestPattern); err != nil {
		return err
	}
	if err := hookevent.ExactTime(f, "received_at", hookevent.EventTimeLayout); err != nil {
		return err
	}
	return checkSigner(f)
}

// Checkpoint is aweb.logs-checkpoint/1: logs' signed witness of a chain head.
// PreviousCheckpointSHA256 is empty on an epoch's first checkpoint.
type Checkpoint struct {
	TeamID                   string
	ChainEpoch               int64
	TeamSeq                  int64
	EventHash                string
	IssuedAt                 string
	LogsOrigin               string
	KID                      string
	DIDKey                   string
	PreviousCheckpointSHA256 string
}

// Fields is the checkpoint's signed object.
func (c Checkpoint) Fields() map[string]any {
	f := map[string]any{
		"v": int64(1), "type": checkpointType,
		"team_id": c.TeamID, "chain_epoch": c.ChainEpoch, "team_seq": c.TeamSeq,
		"event_hash": c.EventHash, "issued_at": c.IssuedAt,
		"logs_origin": c.LogsOrigin, "kid": c.KID, "did_key": c.DIDKey,
	}
	if c.PreviousCheckpointSHA256 != "" {
		f["previous_checkpoint_sha256"] = c.PreviousCheckpointSHA256
	}
	return f
}

func (c Checkpoint) check() error {
	f := c.Fields()
	if err := match(f, "team_id", hookevent.TeamIDPattern); err != nil {
		return err
	}
	if err := counter(f, "chain_epoch", 1); err != nil {
		return err
	}
	if err := counter(f, "team_seq", 0); err != nil {
		return err
	}
	if err := match(f, "event_hash", digestPattern); err != nil {
		return err
	}
	if err := hookevent.ExactTime(f, "issued_at", hookevent.EventTimeLayout); err != nil {
		return err
	}
	if err := checkSigner(f); err != nil {
		return err
	}
	if c.PreviousCheckpointSHA256 != "" {
		return match(f, "previous_checkpoint_sha256", digestPattern)
	}
	return nil
}

// OpenReceipt returns the receipt these bytes hold, signed by the key it
// names. Whether that key is logs' receipt key is the caller's to check.
func OpenReceipt(signingBytes []byte, signature string) (*Receipt, error) {
	f, err := open(signingBytes, signature, receiptPrefix, receiptType, []string{
		"team_id", "event_id", "chain_epoch", "team_seq", "event_hash", "received_at",
		"logs_origin", "kid", "did_key",
	}, nil)
	if err != nil {
		return nil, err
	}
	receipt := &Receipt{
		TeamID: text(f, "team_id"), EventID: text(f, "event_id"), ChainEpoch: integer(f, "chain_epoch"),
		TeamSeq: integer(f, "team_seq"), EventHash: text(f, "event_hash"), ReceivedAt: text(f, "received_at"),
		LogsOrigin: text(f, "logs_origin"), KID: text(f, "kid"), DIDKey: text(f, "did_key"),
	}
	if err := typed(f); err != nil {
		return nil, err
	}
	if err := receipt.check(); err != nil {
		return nil, err
	}
	return receipt, nil
}

// OpenCheckpoint returns the checkpoint these bytes hold, signed by the key it
// names. Whether that key is logs' checkpoint key is the caller's to check.
func OpenCheckpoint(signingBytes []byte, signature string) (*Checkpoint, error) {
	f, err := open(signingBytes, signature, checkpointPrefix, checkpointType, []string{
		"team_id", "chain_epoch", "team_seq", "event_hash", "issued_at", "logs_origin", "kid", "did_key",
	}, []string{"previous_checkpoint_sha256"})
	if err != nil {
		return nil, err
	}
	checkpoint := &Checkpoint{
		TeamID: text(f, "team_id"), ChainEpoch: integer(f, "chain_epoch"), TeamSeq: integer(f, "team_seq"),
		EventHash: text(f, "event_hash"), IssuedAt: text(f, "issued_at"), LogsOrigin: text(f, "logs_origin"),
		KID: text(f, "kid"), DIDKey: text(f, "did_key"),
		PreviousCheckpointSHA256: text(f, "previous_checkpoint_sha256"),
	}
	if err := typed(f); err != nil {
		return nil, err
	}
	if err := checkpoint.check(); err != nil {
		return nil, err
	}
	return checkpoint, nil
}

// open checks an artefact in the contract's order up to its signature.
func open(signingBytes []byte, signature, prefix, kind string, required, optional []string) (map[string]any, error) {
	if !bytes.HasPrefix(signingBytes, []byte(prefix)) {
		return nil, strictjson.Refuse("wrong_prefix", "signing bytes do not start with %q", prefix)
	}
	f, err := strictjson.ParseCanonicalObject(signingBytes[len(prefix):])
	if err != nil {
		return nil, err
	}
	if err := hookevent.CheckKeys(f, "", append([]string{"v", "type"}, required...), optional); err != nil {
		return nil, err
	}
	if v, ok := f["v"].(int64); !ok || v != 1 || f["type"] != kind {
		return nil, strictjson.Refuse("invalid_value", "v or type")
	}
	if err := checkSigner(f); err != nil {
		return nil, err
	}
	if err := hookevent.VerifySignature(f["did_key"].(string), signingBytes, signature); err != nil {
		return nil, err
	}
	return f, nil
}

// typed refuses an artefact field whose JSON type its struct field cannot hold,
// so the struct rebuilt from the bytes is exactly what was signed.
func typed(f map[string]any) error {
	for name, value := range f {
		switch value.(type) {
		case string, int64:
		default:
			return strictjson.Refuse("invalid_value", "%s", name)
		}
	}
	return nil
}

func checkSigner(f map[string]any) error {
	if err := match(f, "logs_origin", hookevent.OriginPattern); err != nil {
		return err
	}
	if err := match(f, "kid", hookevent.KIDPattern); err != nil {
		return err
	}
	return hookevent.Ed25519DIDKey(f, "did_key", "")
}

func prefixedHash(prefix string, f map[string]any) (string, error) {
	canonical, err := strictjson.Canonical(f)
	if err != nil {
		return "", err
	}
	return sha256Hex(append([]byte(prefix), canonical...)), nil
}

func match(f map[string]any, name string, pattern *regexp.Regexp) error {
	value, ok := f[name].(string)
	if !ok || !pattern.MatchString(value) {
		return strictjson.Refuse("invalid_value", "%s", name)
	}
	return nil
}

func counter(f map[string]any, name string, minimum int64) error {
	value, ok := f[name].(int64)
	if !ok || value < minimum || value > strictjson.MaxSafeInteger {
		return strictjson.Refuse("invalid_value", "%s", name)
	}
	return nil
}

func text(f map[string]any, name string) string {
	value, _ := f[name].(string)
	return value
}

func integer(f map[string]any, name string) int64 {
	value, _ := f[name].(int64)
	return value
}
