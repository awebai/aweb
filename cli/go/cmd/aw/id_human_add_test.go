package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	proof "github.com/awebai/approval-service/verify"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// The public corpus's human.add request is checked against what the person
// asked this typed command to do. Receipt verification stays in the shared SDK.
func TestHumanAddBindsTheApprovalToTheRequestedPersonAndIssuer(t *testing.T) {
	r := humanAddRequestVector(t)
	requester := r["requester"].(map[string]any)
	record := &awconfig.HumanRecord{StableID: requester["id"].(string), DIDKey: requester["key"].(string), Domain: r["organisation"].(string)}
	target := r["act"].(map[string]any)["target"].(map[string]any)
	person, key := target["person"].(string), target["identity_key"].(string)
	issuer := r["enforcer"].(map[string]any)["audience"].(string)
	if err := checkHumanAddRequest(r, record, person, key, issuer); err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string][]string{"other person": {"did:aw:other", key, issuer}, "other key": {person, "did:key:other", issuer}, "other issuer": {person, key, "https://other.example"}} {
		t.Run(name, func(t *testing.T) {
			if err := checkHumanAddRequest(r, record, values[0], values[1], values[2]); err == nil {
				t.Fatal("accepted approval for another requested act")
			}
		})
	}
}

func humanAddRequestVector(t *testing.T) map[string]any {
	t.Helper()
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/awebai/approval-service").Output()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(root)), "vectors", "enforcer-requester-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []map[string]any `json:"cases"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	return corpus.Cases[0]["request"].(map[string]any)
}

func TestHumanAddExpiredCommandGivesRecoverableNextStep(t *testing.T) {
	r := humanAddRequestVector(t)
	r["deadline"] = json.Number("1")
	enrollmentObject(r["enforcer"])["audience"] = "https://holder.example"
	requester := enrollmentObject(r["requester"])
	target := enrollmentObject(enrollmentObject(r["act"])["target"])
	h, _, _ := commandUnlockFixture(t, humanPassphrase)
	h.record = &awconfig.HumanRecord{StableID: requester["id"].(string), DIDKey: requester["key"].(string), Domain: r["organisation"].(string)}
	oldH, oldIssuer, oldOrigin, oldPerson, oldKey, oldRestart := activeHuman, humanAddIssuer, humanAddOrigin, humanAddPerson, humanAddKey, humanAddRestart
	activeHuman = h
	humanAddIssuer = enrollmentText(enrollmentObject(r["enforcer"])["audience"])
	humanAddOrigin = ""
	humanAddPerson = target["person"].(string)
	humanAddKey = target["identity_key"].(string)
	humanAddRestart = false
	t.Cleanup(func() {
		activeHuman = oldH
		humanAddIssuer = oldIssuer
		humanAddOrigin = oldOrigin
		humanAddPerson = oldPerson
		humanAddKey = oldKey
		humanAddRestart = oldRestart
	})
	origin := "https://awsign.example"
	if err := saveHumanEnrollment(filepath.Join(h.dir, "approval-binding.json"), map[string]any{"binding": map[string]any{"origin": origin}}); err != nil {
		t.Fatal(err)
	}
	body, _ := proof.Canonical(map[string]any{"person": humanAddPerson, "identity_key": humanAddKey, "approver": h.record.StableID})
	targetURL := humanAddIssuer + "/v1/humans"
	digest := sha256.Sum256(append([]byte(targetURL+"\n"), body...))
	path := filepath.Join(h.dir, fmt.Sprintf("human-add-%x.json", digest))
	raw, _ := proof.Canonical(r)
	if err := approvalRecordWriter(path, origin, targetURL)("request", raw); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	cmd := &cobra.Command{}
	cmd.SetErr(&bytes.Buffer{})
	if err := runIDHumanAdd(cmd, nil); err == nil || !strings.Contains(err.Error(), "--restart") {
		t.Fatalf("expired add is stuck: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("refusal changed original approval")
	}
}
