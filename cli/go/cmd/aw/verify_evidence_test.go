package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awid"
)

// This is the evidence projection of an already checked chain, using the
// seam corpus's explicit Trust port. It makes no live registry/DNS claim.
func TestVerifyProjectsSharedCreationEvidencePerCheckedLink(t *testing.T) {
	root, e := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/awebai/approval-service").Output()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(string(bytes.TrimSpace(root)), "vectors", "issuer-service-enrollment-v1.json"))
	if e != nil {
		t.Fatal(e)
	}
	var data struct {
		Cases []map[string]any `json:"cases"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e = d.Decode(&data); e != nil {
		t.Fatal(e)
	}
	var fixture map[string]any
	for _, c := range data.Cases {
		if c["id"] == "activation-valid" {
			fixture = c
			break
		}
	}
	if fixture == nil {
		t.Fatal("missing pinned creation")
	}
	v := fixture["trust"].(map[string]any)
	observed, _ := v["observed_at"].(json.Number).Int64()
	key, e := base64.RawURLEncoding.DecodeString(v["issuer_public_key"].(string))
	if e != nil {
		t.Fatal(e)
	}
	trust := proof.Trust{Person: v["person"].(string), Organisation: v["organisation"].(string), IdentityKey: v["identity_key"].(string), Certificate: v["certificate"].(string), Issuer: v["issuer"].(string), IssuerPublicKey: key, ObservedAt: observed}
	activation := fixture["activation"].(map[string]any)
	collection, e := proof.Canonical(map[string]any{"v": 1, "links": []any{map[string]any{"certificate": trust.Certificate, "statement": activation["evidence"], "receipt": activation["creation_receipt"]}}})
	if e != nil {
		t.Fatal(e)
	}
	yes := true
	kind := "human"
	out := whoOutput{ID: trust.Person, Domain: trust.Organisation, IDChainResult: awid.IDChainResult{Outcome: "nearest_human", IdentityValid: &yes, HumanID: &trust.Person, Kind: &kind, Reason: "verified"}, Chain: []whoLink{{ID: trust.Person, Kind: kind}}}
	bundle := awid.ReceivedIDChain{"certificates": activation["id_chain"]}
	source := func(context.Context, []any, string, string, string) (*proof.Trust, error) { return &trust, nil }
	out.Evidence = exportEvidenceReports(t.Context(), collection, bundle, out, source)
	if len(out.Evidence) != 1 || out.Evidence[0].Proof.Status != "valid" || out.Evidence[0].IssuerAuthenticatedGrade == nil || *out.Evidence[0].IssuerAuthenticatedGrade != "passkey_uv" {
		t.Fatalf("per-link creation not projected: %+v", out.Evidence)
	}
	if !strings.Contains(formatVerifiedMessage(out), "created with a passkey and user verification; proof checked") {
		t.Fatal(formatVerifiedMessage(out))
	}
	if out.Outcome != "nearest_human" || out.IdentityValid == nil || !*out.IdentityValid {
		t.Fatal("evidence changed chain result")
	}
}
