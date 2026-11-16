package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	source := func(context.Context, []any, string, string, string) (*proof.Trust, string, error) {
		return &trust, trust.IdentityKey, nil
	}
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

// Real SDK status transport, frozen signed public logs, and the shared trust
// verifier; no receipt-supplied first-key value participates.
func TestVerifyEvidenceTrustReadsFirstKeyFromCheckedOwnLog(t *testing.T) {
	v := loadWhoVectors(t)
	for _, tc := range []struct {
		name, status, key string
		ok                bool
	}{
		{"initial", "normal", "alice", true},
		{"rotated", "alice-rotated", "alice_rotated", true},
		{"broken log", "broken-key-history-signature", "alice", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_ENV", "development")
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1/id-certificates/status" {
					t.Errorf("unexpected public read: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(v.Statuses[tc.status])
			}))
			defer peer.Close()
			t.Setenv("AWID_REGISTRY_URL", peer.URL)
			client := awid.NewIDStatusClient(awid.NewAWIDRegistryClient(peer.Client(), nil), nil)
			client.Route = func(context.Context, string) (string, error) { return peer.URL, nil }
			client.Authority = func(context.Context, string) (awid.DomainAuthority, error) {
				return awid.DomainAuthority{DNSName: "_awid.example.com", ControllerDID: v.Keys["root"].DIDKey}, nil
			}
			source := publicEvidenceTrust(client)
			trust, first, err := source(t.Context(), []any{v.Certificates["alice"].Signed}, v.Keys["alice"].DIDAW, v.Keys[tc.key].DIDKey, "example.com")
			if !tc.ok {
				if err == nil || trust != nil || first != "" {
					t.Fatalf("unchecked log supplied trust: %+v %s %v", trust, first, err)
				}
				return
			}
			if err != nil || trust == nil || first != v.Keys["alice"].DIDKey || trust.IdentityKey != v.Keys[tc.key].DIDKey {
				t.Fatalf("own log result: %+v %s %v", trust, first, err)
			}
		})
	}
}
