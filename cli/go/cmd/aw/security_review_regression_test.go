package main

// Regressions for the security review of aweb-acyh at 06e21edfb (probes by
// aweb-protocol-expert-security-fixes), kept under their original names.

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A long-lived caller (aw run's callbacks) holds its policy from before the
// owner key was installed; its next write must still be sealed.
func TestSecurityReviewCachedPolicyAfterInstall(t *testing.T) {
	f := newLocalLogFixture(t)
	cached := localLogPolicyForSelection(f.sel)
	f.installOwnerKey(t, f.teamKey)
	appendInteractionLogForDir(f.sel.WorkingDir, cached, &InteractionEntry{Kind: interactionKindUser, Text: "after-install-secret"})
	raw, err := os.ReadFile(interactionLogPath(f.sel.WorkingDir))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("after-install-secret")) {
		t.Fatal("active run retained no-key policy and appended plaintext after installation")
	}
}

// One global principal's memberships share a communication log; another
// team's plaintext history must not be sealed to this team's owner.
func TestSecurityReviewMigrationDoesNotGiveOtherTeamHistoryToOwner(t *testing.T) {
	f := newLocalLogFixture(t)
	other := *f.sel
	other.TeamID = "other:example.com"
	f.sel.StableID = "did:aw:shared-fixture"
	other.StableID = f.sel.StableID
	if commLogNameForSelection(f.sel) != commLogNameForSelection(&other) {
		t.Fatal("fixture must share the real principal log path")
	}
	appendCommLog(f.logsDir, commLogNameForSelection(&other), localLogPolicyForSelection(&other), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "other-team-history"})
	rec := f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "current-team-entry"})
	for _, raw := range readRawLines(t, f.commLogPath()) {
		var sealed awid.SealedLogLine
		if err := json.Unmarshal([]byte(raw), &sealed); err != nil {
			t.Fatal(err)
		}
		if sealed.KeyID != rec.KeyID {
			continue
		}
		opened, err := awid.OpenLogLine(&sealed, f.ownerKey)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(opened, []byte("other-team-history")) {
			t.Fatal("team A owner key opens team B plaintext history after team A migration")
		}
	}
}

func TestSecurityReviewJSONOwnerOutputEscapesUnicodeControl(t *testing.T) {
	var out bytes.Buffer
	payload, err := json.Marshal(map[string]string{"body": "forged \u009b[2J ‮owned"})
	if err != nil {
		t.Fatal(err)
	}
	if err := printOwnerLogLine(&out, payload, true); err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(out.Bytes(), "\u009b‮") {
		t.Fatal("owner --json output contains raw C1/bidi controls from a forged valid JSON entry")
	}
}

func TestSecurityReviewFreshSelectionPositiveControl(t *testing.T) {
	f := newLocalLogFixture(t)
	f.installOwnerKey(t, f.teamKey)
	appendInteractionLogForDir(f.sel.WorkingDir, localLogPolicyForSelection(f.sel), &InteractionEntry{Timestamp: time.Now().UTC().Format(time.RFC3339), Kind: interactionKindUser, Text: "sealed-control"})
	if got := openAllLines(t, interactionLogPath(f.sel.WorkingDir), f.ownerKey); len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
}
