package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

const testLogPassphrase = "correct horse battery"

// scriptedPassphrases answers prompts in order and counts them.
type scriptedPassphrases struct {
	answers []string
	asked   int
}

func (s *scriptedPassphrases) prompt(string) ([]byte, error) {
	if s.asked >= len(s.answers) {
		return nil, errors.New("unexpected passphrase prompt")
	}
	s.asked++
	return []byte(s.answers[s.asked-1]), nil
}

// ownerWithTeamKey makes this machine the owner of the fixture's team: its
// controller key is in AWID state under the isolated HOME.
func ownerWithTeamKey(t *testing.T, f *localLogFixture) {
	t.Helper()
	domain, name, err := awid.ParseTeamID(localLogTestTeamID)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(domain, name, f.teamKey); err != nil {
		t.Fatal(err)
	}
}

// createSignedLogKey runs the owner's two steps: make the key on the reading
// machine, then sign its record with the local controller key.
func createSignedLogKey(t *testing.T, keychain logKeyStore) *awid.LogKeyRecord {
	t.Helper()
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: keychain, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := signLogKey(logKeySignOptions{Record: rec, OfflineControllerKey: true}); err != nil {
		t.Fatal(err)
	}
	return rec
}

// Making the key needs no controller key: the record comes out unsigned,
// and nothing installs it until it is signed.
func TestLogKeyCreateKeepsTheKeyAndWritesAnUnsignedRecord(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}

	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if rec.TeamKeyDID != "" || rec.Signature != "" {
		t.Fatalf("create must leave the record unsigned: %+v", rec)
	}
	if err := installLogKeyRecord(f.sel, rec); err == nil {
		t.Fatal("an unsigned record must not install")
	}
	blob, err := awconfig.LogKeychain{}.LoadLogKey(rec.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := awid.ImportLogKeyBackup(blob, []byte(testLogPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	line, err := awid.SealLogLine(rec, "", []byte("hello owner"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := awid.OpenLogLine(line, priv); err != nil || string(opened) != "hello owner" {
		t.Fatalf("keychain key does not open the record's lines: %q %v", opened, err)
	}
}

func TestLogKeySignOfflineSignsWithTheLocalControllerKey(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	rec := createSignedLogKey(t, awconfig.LogKeychain{})
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatalf("an offline-signed record must install: %v", err)
	}
}

func TestLogKeySignOfflineRefusesWithoutTheTeamControllerKey(t *testing.T) {
	keyring.MockInit()
	newLocalLogFixture(t)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := *rec
	err = signLogKey(logKeySignOptions{Record: rec, OfflineControllerKey: true})
	if err == nil || !strings.Contains(err.Error(), "only the owner of team") {
		t.Fatalf("err = %v", err)
	}
	if *rec != unsigned {
		t.Fatal("a refused sign changed the record")
	}
}

// Sign never chooses a route itself: no route, or both, is refused, so a
// deployment never falls back to loading a controller key it did not ask for.
func TestLogKeySignRequiresExactlyOneRoute(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	err = signLogKey(logKeySignOptions{Record: rec})
	if err == nil || !strings.Contains(err.Error(), "--offline-controller-key") || !strings.Contains(err.Error(), "--signature") {
		t.Fatalf("no route: err = %v", err)
	}
	if rec.Signature != "" {
		t.Fatal("no route signed the record")
	}
	err = signLogKey(logKeySignOptions{Record: rec, OfflineControllerKey: true, TeamKeyDID: "did:key:z6Mk", Signature: "sig"})
	if err == nil {
		t.Fatal("two routes must be refused")
	}
	if rec.Signature != "" {
		t.Fatal("two routes signed the record")
	}
}

// A signature produced elsewhere over the shared signing bytes is attached
// only after it verifies, and the attached record installs.
func TestLogKeySignAttachesAnExternalSignature(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	teamDID := awid.ComputeDIDKey(f.teamKey.Public().(ed25519.PublicKey))
	external := *rec
	external.TeamKeyDID = teamDID
	signing, err := awid.LogKeyRecordSigningBytes(&external)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.teamKey, signing))

	if err := signLogKey(logKeySignOptions{Record: rec, TeamKeyDID: teamDID, Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.teamKey, []byte("other")))}); err == nil {
		t.Fatal("a signature over other bytes was attached")
	}
	if err := signLogKey(logKeySignOptions{Record: rec, TeamKeyDID: teamDID, Signature: signature}); err != nil {
		t.Fatal(err)
	}
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatalf("the attached record must install: %v", err)
	}
}

func TestLogKeyCreateRefusesBadPassphrases(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	for name, answers := range map[string][]string{
		"mismatch": {testLogPassphrase, testLogPassphrase + "x"},
		"short":    {"short", "short"},
	} {
		prompt := &scriptedPassphrases{answers: answers}
		if _, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()}); err == nil {
			t.Fatalf("%s: passphrase accepted", name)
		}
	}
}

func TestLogKeyInstallAcceptsOnlyTheTeamsOwnerKey(t *testing.T) {
	f := newLocalLogFixture(t)
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := awid.NewLogKeyRecord(localLogTestTeamID, pair.Public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SignLogKeyRecord(rec, stranger); err != nil {
		t.Fatal(err)
	}
	if err := installLogKeyRecord(f.sel, rec); err == nil {
		t.Fatal("a record signed by another key must not install")
	}
	if _, err := awconfig.LoadLogKeyRecord(localLogTestTeamID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused record was installed: %v", err)
	}

	if err := awid.SignLogKeyRecord(rec, f.teamKey); err != nil {
		t.Fatal(err)
	}
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatal(err)
	}
	if key := localLogPolicyForSelection(f.sel).resolve(); key.record == nil || key.record.KeyID != rec.KeyID {
		t.Fatalf("installed key not in use: %+v", key)
	}
}

func TestLogReadOpensEveryRotatedKeyAndPlaintextLines(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	name := commLogNameForSelection(f.sel)
	keychain := awconfig.LogKeychain{}

	appendCommLog(f.logsDir, name, localLogPolicyForSelection(f.sel), &CommLogEntry{Timestamp: "2026-11-13T09:00:00Z", Dir: "recv", Channel: "mail", From: "alice", Body: "plain before any key"})
	for _, body := range []string{"sealed under the first key", "sealed under the second key"} {
		rec := createSignedLogKey(t, keychain)
		if err := installLogKeyRecord(f.sel, rec); err != nil {
			t.Fatal(err)
		}
		appendCommLog(f.logsDir, name, localLogPolicyForSelection(f.sel), &CommLogEntry{Timestamp: "2026-11-13T09:00:00Z", Dir: "recv", Channel: "mail", From: "alice", Body: body})
	}

	var out bytes.Buffer
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	if err := readOwnerLogs(logReadOptions{Files: []string{f.commLogPath()}, Keychain: keychain, Prompt: prompt.prompt, Out: &out}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"plain before any key", "sealed under the first key", "sealed under the second key"} {
		if !strings.Contains(out.String(), body) {
			t.Fatalf("owner output lacks %q:\n%s", body, out.String())
		}
	}
	if prompt.asked != 2 {
		t.Fatalf("want one passphrase prompt per key, got %d", prompt.asked)
	}
}

func TestLogReadPrintsInteractionEntriesAndJSON(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	rec := createSignedLogKey(t, awconfig.LogKeychain{})
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatal(err)
	}
	appendInteractionLogForDir(f.sel.WorkingDir, localLogPolicyForSelection(f.sel), &InteractionEntry{Kind: interactionKindChatIn, MessageID: "c-1", From: "bob", Text: "chat body"})
	path := interactionLogPath(f.sel.WorkingDir)

	var text bytes.Buffer
	if err := readOwnerLogs(logReadOptions{Files: []string{path}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{answers: []string{testLogPassphrase}}).prompt, Out: &text}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "bob") || !strings.Contains(text.String(), "chat body") {
		t.Fatalf("text output:\n%s", text.String())
	}

	var js bytes.Buffer
	if err := readOwnerLogs(logReadOptions{Files: []string{path}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{answers: []string{testLogPassphrase}}).prompt, Out: &js, JSON: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"kind":"chat_in"`) || !strings.Contains(js.String(), `"text":"chat body"`) {
		t.Fatalf("json output:\n%s", js.String())
	}
}

func TestLogReadRefusesAWrongPassphrase(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	rec := createSignedLogKey(t, awconfig.LogKeychain{})
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatal(err)
	}
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "secret"})

	var out bytes.Buffer
	err := readOwnerLogs(logReadOptions{Files: []string{f.commLogPath()}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{answers: []string{"not the passphrase"}}).prompt, Out: &out})
	if err == nil || strings.Contains(out.String(), "secret") {
		t.Fatalf("err = %v, out = %q", err, out.String())
	}
}

func TestLogReadNamesAKeyTheKeychainDoesNotHold(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "secret"})

	err := readOwnerLogs(logReadOptions{Files: []string{filepath.Clean(f.commLogPath())}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{}).prompt, Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "not in this machine's keychain") {
		t.Fatalf("err = %v", err)
	}
}

// Anyone who can write the log can seal a line to the owner's public key, so
// what aw log read prints is untrusted: no terminal control reaches the owner.
func TestLogReadNeutralizesTerminalControlInForgedLines(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	rec := createSignedLogKey(t, awconfig.LogKeychain{})
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "forged.jsonl")
	forged := []string{
		"not json \x1b]0;owned\x07 \x1b[2J \u009b[2J \u202eowned",
		"{\"kind\":\"chat_in\",\"from\":\"\x1b[31mmallory\",\"text\":\"hi\"}",
		`{"ts":"\u001b[2J","dir":"recv","ch":"\u001b]0;owned\u0007","from":"eve","body":"hi"}`,
	}
	for _, plaintext := range forged {
		if err := appendLocalLogLine(path, localLogPolicyForSelection(f.sel), []byte(plaintext), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := appendLocalLogLine(path, localLogPolicyForSelection(f.sel), []byte(`{"kind":"chat_in","from":"bob","text":"esc \u001b[2J inside a valid string"}`), nil); err != nil {
		t.Fatal(err)
	}
	for _, asJSON := range []bool{false, true} {
		var out bytes.Buffer
		if err := readOwnerLogs(logReadOptions{Files: []string{path}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{answers: []string{testLogPassphrase}}).prompt, Out: &out, JSON: asJSON}); err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(out.String(), "\x1b\x07\u009b\u202e") {
			t.Fatalf("json=%v: terminal control reached the owner: %q", asJSON, out.String())
		}
		if strings.Count(out.String(), "\n") != 4 {
			t.Fatalf("json=%v: want one output line per log line: %q", asJSON, out.String())
		}
	}
}
