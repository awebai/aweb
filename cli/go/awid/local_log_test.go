package awid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

const testLogTeamID = "acme:example.com"

func newTestTeamKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, ComputeDIDKey(pub)
}

func newSignedTestLogKey(t *testing.T, teamKey ed25519.PrivateKey) (*LogKeyRecord, *LogKeyPair) {
	t.Helper()
	pair, err := GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewLogKeyRecord(testLogTeamID, pair.Public, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := SignLogKeyRecord(rec, teamKey); err != nil {
		t.Fatal(err)
	}
	return rec, pair
}

func TestLogKeyRecordVerifiesOnlyUnderItsTeamKey(t *testing.T) {
	teamKey, teamDID := newTestTeamKey(t)
	rec, _ := newSignedTestLogKey(t, teamKey)

	if err := VerifyLogKeyRecord(rec, testLogTeamID, teamDID); err != nil {
		t.Fatalf("owner-signed record must verify: %v", err)
	}

	_, otherDID := newTestTeamKey(t)
	if err := VerifyLogKeyRecord(rec, testLogTeamID, otherDID); err == nil {
		t.Fatal("a record must not verify under another team's key")
	}
	if err := VerifyLogKeyRecord(rec, "other:example.com", teamDID); err == nil {
		t.Fatal("a record must not verify for another team id")
	}

	other, err := GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	swapped := *rec
	swapped.PublicKey = other.PublicKeyText()
	if err := VerifyLogKeyRecord(&swapped, testLogTeamID, teamDID); err == nil {
		t.Fatal("a record whose public key was replaced must not verify")
	}

	relabelled := *rec
	relabelled.KeyID = "sha256:not-the-key"
	if err := VerifyLogKeyRecord(&relabelled, testLogTeamID, teamDID); err == nil {
		t.Fatal("a record whose key id does not match its public key must not verify")
	}
}

func TestLogKeyRecordSignatureIsDomainSeparated(t *testing.T) {
	teamKey, teamDID := newTestTeamKey(t)
	rec, _ := newSignedTestLogKey(t, teamKey)
	payload, err := logKeyRecordSignedPayload(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(payload, []byte(LogKeyRecordPrefix)) {
		t.Fatalf("signed payload must start with %q", LogKeyRecordPrefix)
	}

	// A team-key signature over the bare canonical record (no prefix), as any
	// other team-signed object would carry, must not verify as a log key.
	bare := payload[len(LogKeyRecordPrefix):]
	forged := *rec
	forged.Signature = encodeLogBytes(ed25519.Sign(teamKey, bare))
	if err := VerifyLogKeyRecord(&forged, testLogTeamID, teamDID); err == nil {
		t.Fatal("a signature without the log-key prefix must not verify")
	}
}

func TestSealedLogLineOpensOnlyWithTheOwnerKey(t *testing.T) {
	teamKey, _ := newTestTeamKey(t)
	rec, pair := newSignedTestLogKey(t, teamKey)
	plaintext := []byte(`{"ts":"2026-11-13T09:00:00Z","dir":"recv","ch":"mail","body":"the secret"}`)

	line, err := SealLogLine(rec, "tag-1", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("the secret")) || bytes.Contains(encoded, []byte("recv")) {
		t.Fatalf("sealed line leaks plaintext: %s", encoded)
	}
	if line.V != 1 || line.KeyID != rec.KeyID || line.Tag != "tag-1" {
		t.Fatalf("unexpected sealed header: %+v", line)
	}

	opened, err := OpenLogLine(line, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened %q, want %q", opened, plaintext)
	}

	stranger, err := GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLogLine(line, stranger.Private); err == nil {
		t.Fatal("another key must not open the line")
	}

	retagged := *line
	retagged.Tag = "tag-2"
	if _, err := OpenLogLine(&retagged, pair.Private); err == nil {
		t.Fatal("the tag is bound to the ciphertext")
	}
}

func TestLogKeyBackupRoundTripsOnlyWithItsPassphrase(t *testing.T) {
	pair, err := GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery")
	blob, err := ExportLogKeyBackup(pair.Private, pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHumanKeyBackup(blob); err != nil {
		t.Fatalf("a log key backup uses the frozen backup format: %v", err)
	}
	restored, err := ImportLogKeyBackup(blob, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), pair.Private.Bytes()) {
		t.Fatal("restored log key differs")
	}
	if _, err := ImportLogKeyBackup(blob, []byte("wrong passphrase!!")); HumanKeyBackupErrorCode(err) != "backup_decryption_failed" {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := ImportLogKeyBackup(blob, nil); HumanKeyBackupErrorCode(err) != "passphrase_required" {
		t.Fatalf("empty passphrase: %v", err)
	}
	if _, err := ImportHumanKeyBackup(blob, pass); HumanKeyBackupErrorCode(err) != "unsupported_backup" {
		t.Fatalf("a log key must not import as a human signing key: %v", err)
	}

	humanBlob, err := ExportHumanKeyBackup(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportLogKeyBackup(humanBlob, pass); HumanKeyBackupErrorCode(err) != "unsupported_backup" {
		t.Fatalf("a human signing key must not import as a log key: %v", err)
	}
}

func TestLogKeyRecordSigningBytesAreTheSignedPayload(t *testing.T) {
	teamKey, teamDID := newTestTeamKey(t)
	pair, err := GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewLogKeyRecord(testLogTeamID, pair.Public, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LogKeyRecordSigningBytes(rec); err == nil {
		t.Fatal("signing bytes need the signing team key named")
	}
	rec.TeamKeyDID = teamDID
	signing, err := LogKeyRecordSigningBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	want := LogKeyRecordPrefix + `{"created_at":"2026-11-13T09:00:00Z","key_id":"` + rec.KeyID + `","public_key":"` + rec.PublicKey + `","team_id":"acme:example.com","team_key_did":"` + teamDID + `","v":1}`
	if string(signing) != want {
		t.Fatalf("signing bytes\n got %s\nwant %s", signing, want)
	}

	signed := *rec
	signed.TeamKeyDID = ""
	if err := SignLogKeyRecord(&signed, teamKey); err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(teamKey.Public().(ed25519.PublicKey), signing, mustDecodeLogBytes(t, signed.Signature)) {
		t.Fatal("SignLogKeyRecord does not sign the bytes LogKeyRecordSigningBytes returns")
	}

	relabelled := *rec
	relabelled.KeyID = "sha256:not-the-key"
	if _, err := LogKeyRecordSigningBytes(&relabelled); err == nil {
		t.Fatal("a record whose key id does not match its public key has no signing bytes")
	}
}

func TestAttachLogKeyRecordSignatureAcceptsOnlyAVerifyingSignature(t *testing.T) {
	teamKey, teamDID := newTestTeamKey(t)
	pair, err := GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewLogKeyRecord(testLogTeamID, pair.Public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	withKey := *rec
	withKey.TeamKeyDID = teamDID
	signing, err := LogKeyRecordSigningBytes(&withKey)
	if err != nil {
		t.Fatal(err)
	}
	signature := encodeLogBytes(ed25519.Sign(teamKey, signing))

	otherKey, otherDID := newTestTeamKey(t)
	for name, attempt := range map[string]struct{ did, sig string }{
		"another key's did":       {otherDID, signature},
		"another key's signature": {teamDID, encodeLogBytes(ed25519.Sign(otherKey, signing))},
		"bare payload signature":  {teamDID, encodeLogBytes(ed25519.Sign(teamKey, signing[len(LogKeyRecordPrefix):]))},
		"padded encoding":         {teamDID, signature + "=="},
		"not a did":               {"did:key:nope", signature},
	} {
		unsigned := *rec
		if err := AttachLogKeyRecordSignature(&unsigned, attempt.did, attempt.sig); err == nil {
			t.Fatalf("%s: attached", name)
		}
		if unsigned != *rec {
			t.Fatalf("%s: a refused signature changed the record", name)
		}
	}

	if err := AttachLogKeyRecordSignature(rec, teamDID, signature); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLogKeyRecord(rec, testLogTeamID, teamDID); err != nil {
		t.Fatalf("attached record must verify: %v", err)
	}
}

func mustDecodeLogBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeLogBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
