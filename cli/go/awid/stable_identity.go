package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type StableIdentityOutcome string

const (
	StableIdentityVerified  StableIdentityOutcome = "OK_VERIFIED"
	StableIdentityDegraded  StableIdentityOutcome = "OK_DEGRADED"
	StableIdentityHardError StableIdentityOutcome = "HARD_ERROR"
)

type DidKeyEvidence struct {
	Seq            int     `json:"seq"`
	Operation      string  `json:"operation"`
	PreviousDIDKey *string `json:"previous_did_key"`
	NewDIDKey      string  `json:"new_did_key"`
	PrevEntryHash  *string `json:"prev_entry_hash"`
	EntryHash      string  `json:"entry_hash"`
	StateHash      string  `json:"state_hash"`
	AuthorizedBy   string  `json:"authorized_by"`
	Signature      string  `json:"signature"`
	Timestamp      string  `json:"timestamp"`
}

type DidKeyResolution struct {
	DIDAW         string          `json:"did_aw"`
	CurrentDIDKey string          `json:"current_did_key"`
	LogHead       *DidKeyEvidence `json:"log_head"`
}

type StableIdentityVerification struct {
	Outcome       StableIdentityOutcome
	CurrentDIDKey string
	Error         string
}

type VerifiedLogHead struct {
	Seq           int
	EntryHash     string
	StateHash     string
	CurrentDIDKey string
	FetchedAt     time.Time
}

func VerifyDidKeyResolution(res *DidKeyResolution, cached *VerifiedLogHead, now time.Time) (StableIdentityOutcome, *VerifiedLogHead, error) {
	if res == nil {
		return StableIdentityHardError, nil, fmt.Errorf("missing did:key resolution")
	}
	if !strings.HasPrefix(strings.TrimSpace(res.DIDAW), "did:aw:") {
		return StableIdentityHardError, nil, fmt.Errorf("invalid did:aw %q", res.DIDAW)
	}
	if _, err := ExtractPublicKey(strings.TrimSpace(res.CurrentDIDKey)); err != nil {
		return StableIdentityHardError, nil, fmt.Errorf("invalid current did:key: %w", err)
	}
	if res.LogHead == nil {
		return StableIdentityDegraded, nil, nil
	}

	head := res.LogHead
	if head.NewDIDKey != res.CurrentDIDKey {
		return StableIdentityHardError, nil, fmt.Errorf("log_head new_did_key mismatch")
	}
	if head.Seq < 1 {
		return StableIdentityHardError, nil, fmt.Errorf("log_head seq must be >= 1")
	}
	if head.Seq == 1 {
		if head.Operation != "create" {
			return StableIdentityHardError, nil, fmt.Errorf("seq=1 requires create operation")
		}
		if head.PrevEntryHash != nil {
			return StableIdentityHardError, nil, fmt.Errorf("seq=1 requires null prev_entry_hash")
		}
		if head.PreviousDIDKey != nil {
			return StableIdentityHardError, nil, fmt.Errorf("create requires null previous_did_key")
		}
	} else {
		if head.PrevEntryHash == nil || !isLowerHex(*head.PrevEntryHash) {
			return StableIdentityHardError, nil, fmt.Errorf("seq>1 requires hex prev_entry_hash")
		}
		if head.PreviousDIDKey == nil || strings.TrimSpace(*head.PreviousDIDKey) == "" {
			return StableIdentityHardError, nil, fmt.Errorf("seq>1 requires previous_did_key")
		}
		if _, err := ExtractPublicKey(strings.TrimSpace(*head.PreviousDIDKey)); err != nil {
			return StableIdentityHardError, nil, fmt.Errorf("invalid previous_did_key: %w", err)
		}
	}
	if _, err := ExtractPublicKey(strings.TrimSpace(head.AuthorizedBy)); err != nil {
		return StableIdentityHardError, nil, fmt.Errorf("invalid authorized_by did:key: %w", err)
	}
	if !isLowerHex(strings.TrimSpace(head.EntryHash)) {
		return StableIdentityHardError, nil, fmt.Errorf("invalid entry_hash")
	}
	if !isLowerHex(strings.TrimSpace(head.StateHash)) {
		return StableIdentityHardError, nil, fmt.Errorf("invalid state_hash")
	}
	if err := requireCanonicalLogTimestamp(head.Timestamp); err != nil {
		return StableIdentityHardError, nil, err
	}

	payload := CanonicalDidLogPayload(res.DIDAW, head)
	entryHash := sha256.Sum256([]byte(payload))
	if hex.EncodeToString(entryHash[:]) != head.EntryHash {
		return StableIdentityHardError, nil, fmt.Errorf("entry_hash mismatch")
	}

	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(head.Signature))
	if err != nil {
		return StableIdentityHardError, nil, fmt.Errorf("decode log_head signature: %w", err)
	}
	pub, err := ExtractPublicKey(strings.TrimSpace(head.AuthorizedBy))
	if err != nil {
		return StableIdentityHardError, nil, fmt.Errorf("extract authorized_by key: %w", err)
	}
	if !ed25519.Verify(pub, []byte(payload), sig) {
		return StableIdentityHardError, nil, fmt.Errorf("invalid log_head signature")
	}

	if cached != nil {
		switch {
		case head.Seq < cached.Seq:
			return StableIdentityHardError, nil, fmt.Errorf("log_head seq regression")
		case head.Seq == cached.Seq && head.EntryHash != cached.EntryHash:
			return StableIdentityHardError, nil, fmt.Errorf("log_head split view")
		case head.Seq == cached.Seq+1:
			if head.PrevEntryHash == nil || *head.PrevEntryHash != cached.EntryHash {
				return StableIdentityHardError, nil, fmt.Errorf("log_head broken chain")
			}
		case head.Seq > cached.Seq+1:
			return StableIdentityDegraded, nil, nil
		}
	}

	return StableIdentityVerified, &VerifiedLogHead{
		Seq:           head.Seq,
		EntryHash:     head.EntryHash,
		StateHash:     head.StateHash,
		CurrentDIDKey: res.CurrentDIDKey,
		FetchedAt:     now.UTC(),
	}, nil
}

func VerifyDidLogEntries(didAW string, entries []DidKeyEvidence, now time.Time) (*VerifiedLogHead, error) {
	didAW = strings.TrimSpace(didAW)
	if !strings.HasPrefix(didAW, "did:aw:") {
		return nil, fmt.Errorf("invalid did:aw %q", didAW)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("missing audit log entries")
	}

	var cached *VerifiedLogHead
	for index := range entries {
		entry := entries[index]
		resolution := &DidKeyResolution{
			DIDAW:         didAW,
			CurrentDIDKey: strings.TrimSpace(entry.NewDIDKey),
			LogHead:       &entry,
		}
		outcome, nextHead, err := VerifyDidKeyResolution(resolution, cached, now)
		if err != nil {
			return nil, err
		}
		if outcome != StableIdentityVerified || nextHead == nil {
			return nil, fmt.Errorf("unexpected verification outcome %s at seq %d", outcome, entry.Seq)
		}
		if index == 0 && entry.Seq != 1 {
			return nil, fmt.Errorf("audit log must start at seq 1")
		}
		if index > 0 && entry.Seq != entries[index-1].Seq+1 {
			return nil, fmt.Errorf("audit log sequence gap at seq %d", entry.Seq)
		}
		cached = nextHead
	}
	return cached, nil
}

func CanonicalDidLogPayload(didAW string, head *DidKeyEvidence) string {
	var b strings.Builder
	b.WriteByte('{')
	writeJSONField(&b, "authorized_by", head.AuthorizedBy)
	b.WriteByte(',')
	writeJSONField(&b, "did_aw", didAW)
	b.WriteByte(',')
	writeJSONField(&b, "new_did_key", head.NewDIDKey)
	b.WriteByte(',')
	writeJSONField(&b, "operation", head.Operation)
	b.WriteByte(',')
	writeJSONNullableField(&b, "prev_entry_hash", head.PrevEntryHash)
	b.WriteByte(',')
	writeJSONNullableField(&b, "previous_did_key", head.PreviousDIDKey)
	b.WriteByte(',')
	b.WriteString(`"seq":`)
	b.WriteString(fmt.Sprintf("%d", head.Seq))
	b.WriteByte(',')
	writeJSONField(&b, "state_hash", head.StateHash)
	b.WriteByte(',')
	writeJSONField(&b, "timestamp", head.Timestamp)
	b.WriteByte('}')
	return b.String()
}

func writeJSONField(b *strings.Builder, key, value string) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":"`)
	writeEscapedString(b, value)
	b.WriteByte('"')
}

func writeJSONNullableField(b *strings.Builder, key string, value *string) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	if value == nil {
		b.WriteString("null")
		return
	}
	b.WriteByte('"')
	writeEscapedString(b, *value)
	b.WriteByte('"')
}

func isLowerHex(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, ch := range value {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
}

func requireCanonicalLogTimestamp(ts string) error {
	ts = strings.TrimSpace(ts)
	if ts == "" {
		return fmt.Errorf("missing timestamp")
	}
	if strings.Contains(ts, ".") {
		return fmt.Errorf("timestamp must be second precision")
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	return nil
}
