package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestHolderKindBindsThePrincipalOwnEnrollmentDomain(t *testing.T) {
	v := loadWhoVectors(t)
	human := v.Keys["alice"]
	age := float64(0)
	evidence := &awid.IDChainEvidence{Status: v.Statuses["normal"], AgeSeconds: &age,
		NamespaceAuthority: map[string]any{"domain": "example.com", "dns_name": "_awid.example.com", "inherited": false, "controller_key": v.Keys["root"].DIDKey}}
	export := &holderCredentialExport{Principal: human.DIDAW, IDChain: map[string]any{
		"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed},
	}}
	for _, tc := range []struct{ name, enrollment, wantKind, wantCode, reason string }{
		{"enrolled", "example.com", "human", "", ""},
		{"foreign", "other.example.com", "", "principal_not_human", "domain_mismatch"},
		{"unknown", "", "", "principal_status_unavailable", "evidence_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/v1/did/"+human.DIDAW+"/key" {
					t.Errorf("lookup did not use holder principal's key route: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				reads++
				response := map[string]any{"did_aw": human.DIDAW, "current_did_key": human.DIDKey}
				if tc.enrollment != "" {
					response["id_tree"] = map[string]any{"enrolled": true, "domain": tc.enrollment}
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer registry.Close()
			t.Setenv("AWID_REGISTRY_URL", registry.URL)
			t.Setenv("APP_ENV", "development")
			// The certified address is an alias in another domain. It locates
			// key evidence; it must not replace the actual enrollment domain.
			cert := &awid.TeamCertificate{MemberDIDKey: human.DIDKey, MemberDIDAW: human.DIDAW, MemberAddress: "alias.example.com/human"}
			resolver := staticTXTResolver{"_awid.alias.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, registry.URL)}}
			kind, err := holderKind(t.Context(), export, cert, whoOptions{TXTResolver: resolver, Status: whoFixedStatus{evidence}})
			if kind != tc.wantKind || errorCodeOf(err) != tc.wantCode || reads != 1 {
				t.Fatalf("kind=%s err=%v key reads=%d", kind, err, reads)
			}
			if tc.reason != "" && (err == nil || !strings.Contains(err.Error(), tc.reason)) {
				t.Fatalf("distinct refusal reason lost: %v", err)
			}
		})
	}
}
