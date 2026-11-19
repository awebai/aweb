package main

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestParentInstallExistingCertificateForSameLocalKeyOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := realAWIDFixture(t)
	t.Setenv("AWID_REGISTRY_URL", registryURL)
	registry := awid.NewAWIDRegistryClient(nil, nil)
	const domain = "install.example"
	controllerPub, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controller := awid.ComputeDIDKey(controllerPub)
	if _, err := registry.RegisterNamespaceAt(t.Context(), registryURL, domain, controller, controllerKey); err != nil {
		t.Fatalf("register namespace: %v", err)
	}
	if err := awconfig.SaveControllerKey(domain, controllerKey); err != nil {
		t.Fatal(err)
	}
	resolver := staticTXTResolver{awid.AWIDTXTName(domain): {idCreateDNSRecordValue(controller, "")}}
	root := idChildOptions{
		Issuer: childIssuerSelection{AsRoot: true, Domain: domain}, WorkingDir: t.TempDir(),
		RegistryURL: registryURL, TXTResolver: resolver, Now: time.Now,
	}
	newKey := func() ed25519.PrivateKey {
		t.Helper()
		_, key, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	newHome := func(t *testing.T, key ed25519.PrivateKey, global bool) string {
		t.Helper()
		home := filepath.Join(t.TempDir(), ".aw")
		pub := key.Public().(ed25519.PublicKey)
		identity := &awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(pub), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal}
		if global {
			identity.StableID, identity.IdentityScope = awid.ComputeStableID(pub), awid.IdentityModeGlobal
		}
		if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, "identity.yaml"), identity); err != nil {
			t.Fatal(err)
		}
		if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
			t.Fatal(err)
		}
		return home
	}
	// Issue through the commands' exchange, then copy that public certificate
	// to another home with the same key and no outgoing request.
	issue := func(issuer idChildOptions, home string) (map[string]any, []byte) {
		t.Helper()
		invitation, err := executeIDChildInvite(t.Context(), issuer, "agent", "install recipient", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		parent := ""
		asRoot := invitation.Parent["kind"] == "namespace"
		if !asRoot {
			parent = invitation.Parent["id"].(string)
		}
		_, request, err := executeIDParentRequest(idParentOptions{IdentityHome: home, WorkingDir: filepath.Dir(home), Domain: domain}, invitation.InvitationID, parent, asRoot)
		if err != nil {
			t.Fatal(err)
		}
		received, err := executeIDChildReceive(t.Context(), issuer, request)
		if err != nil {
			t.Fatal(err)
		}
		response, err := executeIDChildApprove(t.Context(), issuer, received.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := awid.ParseIDCertificateResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		return parsed["chain"].(map[string]any), response
	}
	subjectKey := newKey()
	subjectHome := newHome(t, subjectKey, false)
	chain, _ := issue(root, subjectHome)
	otherKeyChain, _ := issue(root, newHome(t, newKey(), false))
	parentHome := newHome(t, newKey(), false)
	_, parentResponse := issue(root, parentHome)
	if _, err := executeIDParentImport(t.Context(), idParentOptions{IdentityHome: parentHome, WorkingDir: filepath.Dir(parentHome), Domain: domain, RegistryURL: registryURL, TXTResolver: resolver}, parentResponse); err != nil {
		t.Fatalf("import local parent's issued certificate: %v", err)
	}
	parent := idChildOptions{IdentityHome: parentHome, WorkingDir: filepath.Dir(parentHome), RegistryURL: registryURL, TXTResolver: resolver, Now: time.Now}
	otherParentChain, _ := issue(parent, subjectHome)

	for _, scenario := range []string{"empty", "identical", "another-chain", "another-key", "registered", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			home := newHome(t, subjectKey, scenario == "registered")
			if scenario == "registered" {
				pub := subjectKey.Public().(ed25519.PublicKey)
				if _, err := registry.RegisterIdentity(t.Context(), registryURL, awid.ComputeDIDKey(pub), awid.ComputeStableID(pub), subjectKey); err != nil {
					t.Fatalf("register global subject: %v", err)
				}
			}
			if scenario == "identical" || scenario == "another-key" || scenario == "registered" {
				if err := awconfig.SaveInstalledIDChain(home, chain); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "another-chain" {
				if err := awconfig.SaveInstalledIDChain(home, otherParentChain); err != nil {
					t.Fatal(err)
				}
			}
			before, err := awconfig.LoadInstalledIDChain(home)
			if err != nil {
				t.Fatal(err)
			}
			incoming := chain
			if scenario == "another-key" {
				incoming = otherKeyChain
			}
			raw, err := awid.CanonicalJSONValue(incoming)
			if err != nil {
				t.Fatal(err)
			}
			opts := idParentOptions{IdentityHome: home, WorkingDir: filepath.Dir(home), Domain: domain, RegistryURL: registryURL, TXTResolver: resolver}
			if scenario == "unavailable" {
				// A closed loopback port is an actual transport failure; no
				// substitute registry fabricates an unavailable status response.
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				opts.RegistryURL = "http://" + listener.Addr().String()
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Stat(awconfig.IdentityRequestsDir(home)); !os.IsNotExist(err) {
				t.Fatalf("install target has outgoing request state: %v", err)
			}
			result, err := executeIDParentInstall(t.Context(), opts, []byte(raw))
			after, loadErr := awconfig.LoadInstalledIDChain(home)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if scenario == "empty" || scenario == "identical" {
				if err != nil || result == nil || result.Outcome != "no_human" || result.IdentityValid == nil || !*result.IdentityValid {
					t.Fatalf("install: %+v %v", result, err)
				}
				if after == nil || !reflect.DeepEqual(after.Bundle, incoming) {
					t.Fatal("install did not retain the issued chain")
				}
			} else {
				want := "request_binding_mismatch"
				if scenario == "unavailable" {
					want = "evidence_unavailable"
				}
				if err == nil || awid.IDCertificateErrorCode(err) != want {
					t.Fatalf("install refusal: %v, want %s", err, want)
				}
				if !reflect.DeepEqual(before, after) {
					t.Fatal("refusal changed installed chain")
				}
			}
			retainedKey, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
			if err != nil || !bytes.Equal(retainedKey, subjectKey) {
				t.Fatalf("install changed the home's key: %v", err)
			}
		})
	}
}
