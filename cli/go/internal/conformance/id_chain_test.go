package conformance_test

import (
	"bytes"
	"encoding/json"
	awid "github.com/awebai/aw/awid"
	"reflect"
	"strings"
	"testing"
)

type idChainCase struct {
	Name            string             `json:"name"`
	Chain           []string           `json:"chain"`
	Status          string             `json:"status"`
	Subject         map[string]any     `json:"subject"`
	SubjectPatch    map[string]any     `json:"subject_patch"`
	Expected        awid.IDChainResult `json:"expected"`
	OriginalAuth    string             `json:"original_auth"`
	ExpectedRequest map[string]string  `json:"expected_request"`
	Cache           *struct {
		Age *float64 `json:"age_seconds"`
	} `json:"cache"`
	ExpectedCacheMode  string         `json:"expected_cache_mode"`
	TreeLookup         *bool          `json:"tree_lookup"`
	PresentedChain     *bool          `json:"presented_chain"`
	StatusSource       string         `json:"status_source"`
	NamespaceAuthority map[string]any `json:"namespace_authority"`
}
type idChainVectors struct {
	Certificates map[string]struct {
		Signed map[string]any `json:"signed"`
	} `json:"certificates"`
	Statuses map[string]map[string]any `json:"status_fixtures"`
	Cases    []idChainCase             `json:"verification_cases"`
}

func loadIDChainVectors(t *testing.T) idChainVectors {
	t.Helper()
	var v idChainVectors
	d := json.NewDecoder(bytes.NewReader(readRootVector(t, "id-certificates-v1.json")))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestIDChainFinalVectors(t *testing.T) {
	v := loadIDChainVectors(t)
	if len(v.Cases) != 122 {
		t.Fatalf("case count=%d want122", len(v.Cases))
	}
	names := map[string]bool{}
	for _, c := range v.Cases {
		if names[c.Name] {
			t.Fatal("duplicate case", c.Name)
		}
		names[c.Name] = true
	}
	for _, name := range []string{"namespace-overlapping-replaced-successor-unavailable", "namespace-unretired-predecessor-unavailable", "root-replacement-cutoff-in-historical-human-parent", "namespace-epoch-at-retirement-unavailable", "cached-status-age-60", "cached-status-age-61"} {
		if !names[name] {
			t.Fatal("missing required boundary", name)
		}
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			values := map[string]any{}
			for k, x := range c.Subject {
				values[k] = x
			}
			for k, x := range c.SubjectPatch {
				values[k] = x
			}
			text := func(k string) string { s, _ := values[k].(string); return s }
			subject := awid.IDChainSubject{ID: text("id"), DIDKey: text("did_key"), TeamMemberDIDAW: text("team_member_did_aw"), TeamMemberDIDKey: text("team_member_did_key")}
			var bundle map[string]any
			if len(c.Chain) > 0 && (c.PresentedChain == nil || *c.PresentedChain) {
				certs := []any{}
				for _, n := range c.Chain {
					certs = append(certs, v.Certificates[n].Signed)
				}
				bundle = map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certs}
			}
			status := v.Statuses[c.Status]
			domain := status["domain"].(string)
			authority := c.NamespaceAuthority
			if authority == nil {
				epochs := status["namespace"].(map[string]any)["epochs"].([]any)
				current := epochs[len(epochs)-1].(map[string]any)["did_key"]
				authority = map[string]any{"domain": domain, "dns_name": "_awid." + domain, "inherited": false, "controller_key": current}
			}
			age := 0.0
			evidence := &awid.IDChainEvidence{Status: status, NamespaceAuthority: authority, AgeSeconds: &age}
			if c.Cache != nil {
				evidence.AgeSeconds = c.Cache.Age
			}
			if c.StatusSource == "caller" {
				evidence = nil
			}
			got := awid.VerifyIDChain(bundle, subject, evidence, domain)
			if !reflect.DeepEqual(got, c.Expected) {
				t.Fatalf("got %+v want %+v", got, c.Expected)
			}
			for key, human := range map[string]bool{"ordinary": false, "human_required": true} {
				if got := awid.IDRequestDisposition(got, subject, c.OriginalAuth == "passed", human); got != c.ExpectedRequest[key] {
					t.Fatalf("%s=%s want %s", key, got, c.ExpectedRequest[key])
				}
			}
			if c.TreeLookup != nil {
				request, err := awid.IDStatusRequest(bundle, subject, domain)
				if err != nil {
					t.Fatal(err)
				}
				if (request != nil) != *c.TreeLookup {
					t.Fatal("wrong status lookup decision")
				}
			}
			if c.ExpectedCacheMode != "" {
				if got := awid.IDStatusCacheMode(c.Cache.Age); got != c.ExpectedCacheMode {
					t.Fatalf("cache=%s", got)
				}
			}
		})
	}
}

func TestIDChainInvalidStatusIsUnavailable(t *testing.T) {
	for _, mutation := range []string{"extra", "duplicate", "missing", "wrong-domain", "over-limit", "revocation-after-witness"} {
		t.Run(mutation, func(t *testing.T) {
			v := loadIDChainVectors(t)
			c := v.Cases[0]
			status := v.Statuses[c.Status]
			domain := status["domain"].(string)
			subject := awid.IDChainSubject{ID: c.Subject["id"].(string), DIDKey: c.Subject["did_key"].(string), TeamMemberDIDKey: c.Subject["team_member_did_key"].(string)}
			certs := []any{}
			for _, n := range c.Chain {
				certs = append(certs, v.Certificates[n].Signed)
			}
			bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certs}
			epochs := status["namespace"].(map[string]any)["epochs"].([]any)
			key := epochs[len(epochs)-1].(map[string]any)["did_key"]
			age := 0.0
			evidence := &awid.IDChainEvidence{Status: status, AgeSeconds: &age, NamespaceAuthority: map[string]any{"domain": domain, "dns_name": "_awid." + domain, "inherited": false, "controller_key": key}}
			switch mutation {
			case "extra":
				status["extra"] = true
			case "duplicate":
				status["identities"] = append(status["identities"].([]any), status["identities"].([]any)[0])
			case "missing":
				delete(status, "missing")
			case "wrong-domain":
				status["domain"] = "attacker.example"
			case "over-limit":
				status["missing"] = []any{strings.Repeat("x", 131072)}
			case "revocation-after-witness":
				status["identities"].([]any)[0].(map[string]any)["revocation"] = map[string]any{"revoked_at": "2026-10-26T00:10:00.000000Z", "effective_from": "2026-10-26T00:11:00.000000Z"}

			}
			if got := awid.VerifyIDChain(bundle, subject, evidence, domain); got.Reason != "evidence_unavailable" || got.IdentityValid != nil {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
func TestIDChainOmittedLocalDoesNotPlanALookup(t *testing.T) {
	v := loadIDChainVectors(t)
	c := v.Cases[0]
	subject := awid.IDChainSubject{ID: c.Subject["id"].(string), DIDKey: c.Subject["did_key"].(string)}
	request, err := awid.IDStatusRequest(nil, subject, "")
	if err != nil || request != nil {
		t.Fatalf("request=%v err=%v", request, err)
	}
	for _, candidate := range v.Cases {
		if strings.HasPrefix(candidate.Subject["id"].(string), "did:aw:") {
			subject.ID = candidate.Subject["id"].(string)
			_, err = awid.IDStatusRequest(nil, subject, "")
			if awid.IDCertificateErrorCode(err) != "evidence_unavailable" {
				t.Fatal("missing private domain guessed")
			}
			break
		}
	}
}
