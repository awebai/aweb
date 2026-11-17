package main

import (
	"bytes"
	"encoding/json"
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
	r := corpus.Cases[0]["request"].(map[string]any)
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
