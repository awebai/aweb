package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestParentInstallExistingCertificateForSameLocalKeyOnly(t *testing.T) {
	for _, scenario := range []string{"empty", "identical", "another-chain", "another-key", "registered", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AW_CONFIG_PATH", "")
			v := adoptionVectors(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1/id-certificates/status" {
					t.Errorf("unexpected %s", r.URL.Path)
				}
				if scenario == "unavailable" {
					http.Error(w, "unavailable", 503)
					return
				}
				json.NewEncoder(w).Encode(v.Statuses["normal"])
			}))
			defer server.Close()
			t.Setenv("AWID_REGISTRY_URL", server.URL)
			chain := adoptionChain(v.Certificates["root-agent"].Signed)
			home := adoptionHome(t, v, scenario == "registered", chain)
			if scenario == "empty" || scenario == "unavailable" {
				if err := os.Remove(filepath.Join(home, "id-chain.json")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "another-chain" {
				cert := adoptionSigned(t, v.Keys["root_agent"].DIDKey, map[string]any{"kind": "identity", "id": v.Keys["alice"].DIDAW}, v.key(t, "alice"))
				if err := awconfig.SaveInstalledIDChain(home, adoptionChain(v.Certificates["alice"].Signed, cert)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "another-key" {
				chain = adoptionChain(v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed)
			}
			before, err := awconfig.LoadInstalledIDChain(home)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := awid.CanonicalJSONValue(chain)
			if err != nil {
				t.Fatal(err)
			}
			opts := idParentOptions{IdentityHome: home, WorkingDir: filepath.Dir(home), Domain: "example.com", RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}}}
			result, err := executeIDParentInstall(t.Context(), opts, []byte(raw))
			if scenario == "empty" || scenario == "identical" {
				if err != nil || result.Outcome != "no_human" {
					t.Fatalf("install: %+v %v", result, err)
				}
			} else {
				if err == nil {
					t.Fatal("ineligible install succeeded")
				}
				after, _ := awconfig.LoadInstalledIDChain(home)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("refusal changed installed chain")
				}
			}
		})
	}
}
