package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIDCreateDelegatedControllerPreflight(t *testing.T) {
	childPub, childPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	childKey := awid.ComputeDIDKey(childPub)
	parentKey := "did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2"
	for _, mutation := range []string{"valid", "absent", "unsigned", "wrong-domain", "wrong-parent", "wrong-key"} {
		t.Run(mutation, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/v1/namespaces/child.example.com" {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
				if mutation == "absent" {
					http.NotFound(w, r)
					return
				}
				delegation := map[string]any{"parent_domain": "example.com", "parent_controller_key": parentKey, "controller_key": childKey}
				ns := map[string]any{"domain": "child.example.com", "controller_did": childKey, "delegation": delegation}
				switch mutation {
				case "unsigned":
					delete(ns, "delegation")
				case "wrong-domain":
					ns["domain"] = "other.example.com"
				case "wrong-parent":
					delegation["parent_domain"] = "other.example.com"
				case "wrong-key":
					delegation["parent_controller_key"] = childKey
				}
				_ = json.NewEncoder(w).Encode(ns)
			}))
			defer srv.Close()
			resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(parentKey, "")}}
			err := verifyIDCreateDomainAuthority(context.Background(), resolver, "child.example.com", childKey, srv.URL)
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("create preflight err=%v", err)
			}
			err = checkRootController(context.Background(), resolver, "child.example.com", srv.URL, childPrivate)
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("root preflight err=%v", err)
			}
		})
	}
}

func TestIDNamespaceCheckTXTRequiresOwnRecordForBYOTSetup(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prepared, err := executeIDNamespacePrepareController(idNamespacePrepareControllerOptions{Domain: "child.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticTXTResolver{"_awid.example.com": {prepared.DNSValue}}
	if _, err := executeIDNamespaceCheckTXT(idNamespaceCheckTXTOptions{Domain: "child.example.com", TXTResolver: resolver}); err == nil {
		t.Fatal("ancestor TXT cannot confirm BYOT own-record propagation")
	}
	resolver["_awid.child.example.com"] = []string{prepared.DNSValue}
	if _, err := executeIDNamespaceCheckTXT(idNamespaceCheckTXTOptions{Domain: "child.example.com", TXTResolver: resolver}); err != nil {
		t.Fatal(err)
	}
}

func TestIDCreateOwnTXTOverridesMatchingAncestor(t *testing.T) {
	const domain = "child.example.com"
	run := newParentCreateRun(t, awid.DefaultAWIDRegistryURL)
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	local := awid.ComputeDIDKey(pub)
	otherPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	other := awid.ComputeDIDKey(otherPub)
	if err := awconfig.SaveControllerKey(domain, key); err != nil {
		t.Fatal(err)
	}
	resolver := staticTXTResolver{
		"_awid.child.example.com": {idCreateDNSRecordValue(other, "")},
		"_awid.example.com":       {idCreateDNSRecordValue(local, "")},
	}
	// Exercise creation, including its shared discovery path. An ancestor
	// naming our own key must not override the conflicting child record.
	_, err = executeIDCreate(run.workingDir, idCreateOptions{
		Name: "coordinator", Domain: domain, RegistryURL: awid.DefaultAWIDRegistryURL,
		RootParent: true, SkipDNSVerify: true, TXTResolver: resolver,
	})
	if err == nil || !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), local) {
		t.Fatalf("expected controller mismatch for %s versus %s, got %v", other, local, err)
	}
	run.assertNoAgent()
	// The valid neighbour keeps using the child's own key even when its
	// ancestor names a different controller; no registry read is required.
	resolver["_awid.child.example.com"] = []string{idCreateDNSRecordValue(local, "")}
	resolver["_awid.example.com"] = []string{idCreateDNSRecordValue(other, "")}
	if err := verifyIDCreateDomainAuthority(context.Background(), resolver, domain, local, awid.DefaultAWIDRegistryURL); err != nil {
		t.Fatalf("matching own record refused: %v", err)
	}
}
