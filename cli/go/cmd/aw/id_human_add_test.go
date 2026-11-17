package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	proof "github.com/awebai/approval-service/verify"
	"github.com/spf13/cobra"
	"net"
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

func TestHumanAddIssuedPacketUsesTheIndependentController(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err = d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	signed := enrollmentObject(enrollmentObject(enrollmentObject(v["certificates"])["alice"])["signed"])
	cert := enrollmentObject(signed["certificate"])
	key := enrollmentText(enrollmentObject(enrollmentObject(v["keys"])["alice"])["did_key"])
	person, domain, controller := enrollmentText(cert["id"]), enrollmentText(cert["domain"]), enrollmentText(cert["issuer_key"])
	packet := map[string]any{"state": "issued", "person": person, "identity_key": key, "certificate": signed}
	if err := checkHumanAddIssued(packet, person, key, domain, controller); err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string][]string{
		"wrong person":     {"did:aw:other", key, domain, controller},
		"wrong key":        {person, controller, domain, controller},
		"wrong domain":     {person, key, "other.test", controller},
		"wrong controller": {person, key, domain, key},
	} {
		t.Run(name, func(t *testing.T) {
			if checkHumanAddIssued(packet, values[0], values[1], values[2], values[3]) == nil {
				t.Fatal("accepted unrelated issued certificate")
			}
		})
	}
}

func TestHumanAddWithoutEnrollmentReachesTheIssuer(t *testing.T) {
	r := humanAddRequestVector(t)
	h, prompts, _ := commandUnlockFixture(t, humanPassphrase)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://" + listener.Addr().String()
	_ = listener.Close()
	target := enrollmentObject(enrollmentObject(r["act"])["target"])
	oldH, oldIssuer, oldOrigin, oldPerson, oldKey, oldOut, oldRestart := activeHuman, humanAddIssuer, humanAddOrigin, humanAddPerson, humanAddKey, humanAddOut, humanAddRestart
	activeHuman, humanAddIssuer, humanAddOrigin = h, issuer, ""
	humanAddPerson, humanAddKey = enrollmentText(target["person"]), enrollmentText(target["identity_key"])
	humanAddOut, humanAddRestart = "", false
	t.Cleanup(func() {
		activeHuman, humanAddIssuer, humanAddOrigin, humanAddPerson, humanAddKey, humanAddOut, humanAddRestart = oldH, oldIssuer, oldOrigin, oldPerson, oldKey, oldOut, oldRestart
	})
	// An explicit issuer must not depend on unrelated, unfinished enrollment
	// state when no approval is required.
	if err := os.WriteFile(filepath.Join(h.dir, "enrollment-session.json"), []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	cmd.SetErr(&bytes.Buffer{})
	err = runIDHumanAdd(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "connect: connection refused") {
		t.Fatalf("unenrolled person must reach the actual issuer connection, not require awsign first: %v", err)
	}
	if len(*prompts) != 1 {
		t.Fatalf("issuer request signed with %d unlocks", len(*prompts))
	}
	if _, err := os.Stat(filepath.Join(h.dir, "approval-binding.json")); !os.IsNotExist(err) {
		t.Fatal("test unexpectedly has enrollment")
	}
}
