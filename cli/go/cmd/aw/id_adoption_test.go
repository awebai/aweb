package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type adoptionFixture struct {
	Keys map[string]struct {
		Seed   string `json:"seed_hex"`
		DIDKey string `json:"did_key"`
		DIDAW  string `json:"did_aw"`
	}
	Certificates map[string]struct{ Signed map[string]any }
	Statuses     map[string]map[string]any `json:"status_fixtures"`
}

func adoptionVectors(t *testing.T) adoptionFixture {
	t.Helper()
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v adoptionFixture
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
func (v adoptionFixture) key(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(v.Keys[name].Seed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}
func adoptionChain(certificates ...any) map[string]any {
	return map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates}
}
func adoptionSigned(t *testing.T, id string, parent map[string]any, key ed25519.PrivateKey) map[string]any {
	return adoptionSignedInDomain(t, id, parent, key, "example.com")
}
func adoptionSignedInDomain(t *testing.T, id string, parent map[string]any, key ed25519.PrivateKey, domain string) map[string]any {
	t.Helper()
	c := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": id, "domain": domain, "parent": parent, "kind": "agent", "issuer_key": awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), "issued_at": "2026-10-26T00:20:00Z"}
	payload, err := awid.IDCertificateSigningBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"certificate": c, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))}
}
func adoptionHome(t *testing.T, v adoptionFixture, global bool, chain map[string]any) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), ".aw")
	name := "root_agent"
	scope := awid.IdentityModeLocal
	stable := ""
	if global {
		name = "global_agent"
		scope = awid.IdentityModeGlobal
		stable = v.Keys[name].DIDAW
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, "identity.yaml"), &awconfig.WorktreeIdentity{DID: v.Keys[name].DIDKey, StableID: stable, Custody: awid.CustodySelf, IdentityScope: scope}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), v.key(t, name)); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveInstalledIDChain(home, chain); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestParentRequestAllowsOnlyOrganizationOnlyAdoption(t *testing.T) {
	for _, global := range []bool{false, true} {
		for _, scenario := range []string{"organization", "human", "agent", "root-again", "other-domain", "other-subject", "local-parent"} {
			t.Run(map[bool]string{false: "local", true: "global"}[global]+"/"+scenario, func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				t.Setenv("AW_CONFIG_PATH", "")
				v := adoptionVectors(t)
				old := v.Certificates["root-agent"].Signed
				id := v.Keys["root_agent"].DIDKey
				if global {
					old = v.Certificates["registered-root-agent"].Signed
					id = v.Keys["global_agent"].DIDAW
				}
				chain := adoptionChain(old)
				parent := v.Keys["alice"].DIDAW
				domain := "example.com"
				root := false
				switch scenario {
				case "human":
					chain = adoptionChain(v.Certificates["alice"].Signed, adoptionSigned(t, id, map[string]any{"kind": "identity", "id": parent}, v.key(t, "alice")))
				case "agent":
					chain = adoptionChain(v.Certificates["root-agent"].Signed, adoptionSigned(t, id, map[string]any{"kind": "identity", "id": v.Keys["root_agent"].DIDKey}, v.key(t, "root_agent")))
				case "root-again":
					parent = ""
					root = true
				case "other-domain":
					domain = "other.example"
				case "other-subject":
					chain = adoptionChain(v.Certificates["alice"].Signed)
				case "local-parent":
					parent = v.Keys["coordinator"].DIDKey
				}
				home := adoptionHome(t, v, global, chain)
				_, raw, err := executeIDParentRequest(idParentOptions{IdentityHome: home, WorkingDir: filepath.Dir(home), Domain: domain}, "11111111-1111-4111-8111-111111111111", parent, root)
				if scenario == "organization" || (!global && scenario == "other-domain") {
					if err != nil {
						t.Fatal(err)
					}
					signed, err := awid.ParseIDCertificateRequest(raw)
					if err != nil {
						t.Fatal(err)
					}
					req := signed["request"].(map[string]any)
					if req["id"] != id || req["subject_key"] != v.Keys[map[bool]string{false: "root_agent", true: "global_agent"}[global]].DIDKey {
						t.Fatal(req)
					}
				} else if err == nil {
					t.Fatal("ineligible adoption exported")
				}
				if global && scenario == "other-domain" {
					want := "this agent is registered under example.com; a person whose home domain is other.example cannot adopt it yet"
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("cross-domain refusal: %v", err)
					}
					entries, readErr := os.ReadDir(awconfig.IdentityRequestsDir(home))
					if !os.IsNotExist(readErr) || len(entries) != 0 {
						t.Fatal("cross-domain request was signed or retained")
					}
				}
				installed, err := awconfig.LoadInstalledIDChain(home)
				if err != nil {
					t.Fatal(err)
				}
				// SaveInstalledIDChain normalizes numeric values; compare canonical bytes.
				a, _ := awid.CanonicalJSONValue(installed.Bundle)
				b, _ := awid.CanonicalJSONValue(chain)
				if a != b {
					t.Fatal("request changed chain")
				}
			})
		}
	}
}

func TestParentImportAdoptsOrganizationOnlyAgentOnce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	v := adoptionVectors(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/id-certificates/status" {
			t.Errorf("unexpected %s", r.URL.Path)
			http.Error(w, "unexpected", 500)
			return
		}
		json.NewEncoder(w).Encode(v.Statuses["normal"])
	}))
	defer server.Close()
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	home := adoptionHome(t, v, false, adoptionChain(v.Certificates["root-agent"].Signed))
	opts := idParentOptions{IdentityHome: home, WorkingDir: filepath.Dir(home), Domain: "example.com", RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}}}
	out, _, err := executeIDParentRequest(opts, "11111111-1111-4111-8111-111111111111", v.Keys["alice"].DIDAW, false)
	if err != nil {
		t.Fatal(err)
	}
	cert := adoptionSigned(t, v.Keys["root_agent"].DIDKey, map[string]any{"kind": "identity", "id": v.Keys["alice"].DIDAW}, v.key(t, "alice"))
	chain := adoptionChain(v.Certificates["alice"].Signed, cert)
	raw, err := awid.EncodeIDCertificateResponse(out.RequestID, chain)
	if err != nil {
		t.Fatal(err)
	}
	// An unsolicited response never replaces the installed namespace chain.
	wrong, err := awid.EncodeIDCertificateResponse("22222222-2222-4222-8222-222222222222", chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeIDParentImport(t.Context(), opts, wrong); awid.IDCertificateErrorCode(err) != "request_binding_mismatch" {
		t.Fatal(err)
	}
	if _, err := executeIDParentImport(t.Context(), opts, raw); err != nil {
		t.Fatal(err)
	}
	installed, err := awconfig.LoadInstalledIDChain(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(installed.Bundle["certificates"].([]any)) != 2 {
		t.Fatal(installed)
	}
	if _, _, err := executeIDParentRequest(opts, "22222222-2222-4222-8222-222222222222", v.Keys["bob"].DIDAW, false); err == nil {
		t.Fatal("second adoption allowed")
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(home, "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(identity.DID, v.Keys["root_agent"].DIDKey) {
		t.Fatal("identity changed")
	}
}

// A queued CSR is not permission to replace the person installed by another
// completed adoption. Nor may a valid agent signature stand in for a person.
func TestParentImportAdoptionRefusesAgentParentAndStaleRequest(t *testing.T) {
	for _, scenario := range []string{"agent-parent", "already-adopted"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AW_CONFIG_PATH", "")
			v := adoptionVectors(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(v.Statuses["normal"]) }))
			defer server.Close()
			t.Setenv("AWID_REGISTRY_URL", server.URL)
			home := adoptionHome(t, v, false, adoptionChain(v.Certificates["root-agent"].Signed))
			opts := idParentOptions{IdentityHome: home, WorkingDir: filepath.Dir(home), Domain: "example.com", RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}}}
			target := v.Keys["alice"].DIDAW
			signer := "alice"
			prefix := []any{v.Certificates["alice"].Signed}
			if scenario == "agent-parent" {
				target = v.Keys["global_agent"].DIDAW
				signer = "global_agent"
				prefix = []any{v.Certificates["registered-root-agent"].Signed}
			}
			out, _, err := executeIDParentRequest(opts, "11111111-1111-4111-8111-111111111111", target, false)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "already-adopted" {
				other := adoptionSigned(t, v.Keys["root_agent"].DIDKey, map[string]any{"kind": "identity", "id": v.Keys["bob"].DIDAW}, v.key(t, "bob"))
				if err := awconfig.SaveInstalledIDChain(home, adoptionChain(v.Certificates["alice"].Signed, v.Certificates["bob"].Signed, other)); err != nil {
					t.Fatal(err)
				}
			}
			before, err := awconfig.LoadInstalledIDChain(home)
			if err != nil {
				t.Fatal(err)
			}
			cert := adoptionSigned(t, v.Keys["root_agent"].DIDKey, map[string]any{"kind": "identity", "id": target}, v.key(t, signer))
			raw, err := awid.EncodeIDCertificateResponse(out.RequestID, adoptionChain(append(prefix, cert)...))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executeIDParentImport(t.Context(), opts, raw); awid.IDCertificateErrorCode(err) != "request_binding_mismatch" {
				t.Fatalf("ineligible replacement: %v", err)
			}
			after, err := awconfig.LoadInstalledIDChain(home)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("refusal replaced installed chain")
			}
		})
	}
}

func TestRegisteredAdoptionRetainsOldChainUntilAtomicRegistrationAndRetriesExactHead(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	v := adoptionVectors(t)
	old := v.Certificates["registered-root-agent"].Signed
	expected, _ := awid.IDCertificateID(old["certificate"].(map[string]any))
	// Before adoption the registry and installed certificate agree on the
	// namespace head. The register endpoint then atomically replaces it.
	for _, value := range v.Statuses["normal"]["identities"].([]any) {
		row := value.(map[string]any)
		if row["id"] == v.Keys["global_agent"].DIDAW {
			row["current_certificate_id"] = expected
			row["certificates"] = []any{map[string]any{"signed": old, "registered_at": "2026-10-26T00:04:00.000000Z", "superseded_at": nil, "issuer_key_seq": 1}}
		}
	}
	writes := 0
	fail := true
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/id-certificates/status":
			json.NewEncoder(w).Encode(v.Statuses["normal"])
		case "/v1/id-certificates/register":
			writes++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["expected_head"] != expected || body["invitation_id"] != "11111111-1111-4111-8111-111111111111" {
				t.Errorf("atomic binding lost: %v", body)
			}
			if fail {
				http.Error(w, "temporary", 503)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"registered_at": "2026-11-16T00:00:00.000000Z"})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer server.Close()
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	home := adoptionHome(t, v, true, adoptionChain(old))
	opts := idParentOptions{IdentityHome: home, WorkingDir: filepath.Dir(home), Domain: "example.com", RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}}}
	out, _, err := executeIDParentRequest(opts, "11111111-1111-4111-8111-111111111111", v.Keys["alice"].DIDAW, false)
	if err != nil {
		t.Fatal(err)
	}
	cert := adoptionSigned(t, v.Keys["global_agent"].DIDAW, map[string]any{"kind": "identity", "id": v.Keys["alice"].DIDAW}, v.key(t, "alice"))
	raw, err := awid.EncodeIDCertificateResponse(out.RequestID, adoptionChain(v.Certificates["alice"].Signed, cert))
	if err != nil {
		t.Fatal(err)
	}
	opts.NoRegister = true
	if _, err := executeIDParentImport(t.Context(), opts, raw); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatal("--no-register wrote registry")
	}
	opts.NoRegister = false
	if _, err := executeIDParentImport(t.Context(), opts, raw); err == nil {
		t.Fatal("registry failure hidden")
	}
	installed, err := awconfig.LoadInstalledIDChain(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(installed.Bundle["certificates"].([]any)) != 1 {
		t.Fatal("failed adoption replaced working chain")
	}
	fail = false
	imported, err := executeIDParentImport(t.Context(), opts, raw)
	if err != nil || imported.Registration != "registered" {
		t.Fatalf("retry: %+v %v", imported, err)
	}
	if writes != 2 {
		t.Fatalf("writes=%d", writes)
	}
	installed, err = awconfig.LoadInstalledIDChain(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(installed.Bundle["certificates"].([]any)) != 2 {
		t.Fatal("registered adoption not installed")
	}
}

func TestChildSpawnedBeforeLocalParentAdoptionRefreshesToHuman(t *testing.T) {
	for _, scenario := range []string{"success", "unrecorded", "revoked-parent"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AW_CONFIG_PATH", "")
			v := adoptionVectors(t)
			statusName := "normal"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/id-certificates/status" {
					t.Errorf("unexpected %s", r.URL.Path)
				}
				json.NewEncoder(w).Encode(v.Statuses[statusName])
			}))
			defer server.Close()
			t.Setenv("AWID_REGISTRY_URL", server.URL)
			resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}}
			registry := awid.NewAWIDRegistryClient(server.Client(), resolver)
			registry.DefaultRegistryURL = server.URL
			parentID := v.Keys["root_agent"].DIDKey
			childID := v.Keys["coordinator"].DIDKey
			parentChain := adoptionChain(v.Certificates["root-agent"].Signed)
			parentHome := adoptionHome(t, v, false, parentChain)
			issuance := awconfig.IDIssuanceFileStore{Dir: awconfig.IdentityIssuanceDir(parentHome)}
			evidence := idStatusAt(registry, resolver, server.URL).IDChainEvidence(t.Context(), parentChain, awid.IDChainSubject{ID: parentID, DIDKey: parentID}, "example.com")
			childChain, err := awid.IssueIDChild(issuance, awid.IDChild{ID: childID, Domain: "example.com", Parent: map[string]any{"kind": "identity", "id": parentID}, Kind: "agent"}, parentChain["certificates"].([]any), evidence, awid.KeySigner(v.key(t, "root_agent")), time.Date(2026, 10, 26, 0, 21, 0, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			childHome := filepath.Join(t.TempDir(), ".aw")
			if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(childHome, "identity.yaml"), &awconfig.WorktreeIdentity{DID: childID, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal}); err != nil {
				t.Fatal(err)
			}
			if err := awid.SaveSigningKey(filepath.Join(childHome, "signing.key"), v.key(t, "coordinator")); err != nil {
				t.Fatal(err)
			}
			if err := awconfig.SaveInstalledIDChain(childHome, childChain); err != nil {
				t.Fatal(err)
			}
			assertWho := func(want string) {
				t.Helper()
				chain, err := awconfig.LoadInstalledIDChain(childHome)
				if err != nil {
					t.Fatal(err)
				}
				evidence := idStatusAt(registry, resolver, server.URL).IDChainEvidence(t.Context(), chain.Bundle, awid.IDChainSubject{ID: childID, DIDKey: childID}, "example.com")
				verdict := awid.VerifyIDChain(chain.Bundle, awid.IDChainSubject{ID: childID, DIDKey: childID}, evidence, "example.com")
				if verdict.Outcome != want {
					t.Fatalf("who: %+v", verdict)
				}
				if want == "nearest_human" && (verdict.HumanID == nil || *verdict.HumanID != v.Keys["alice"].DIDAW) {
					t.Fatal(verdict)
				}
			}
			assertWho("no_human")
			parentOpts := idParentOptions{IdentityHome: parentHome, WorkingDir: filepath.Dir(parentHome), Domain: "example.com", RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: resolver}
			request, _, err := executeIDParentRequest(parentOpts, "11111111-1111-4111-8111-111111111111", v.Keys["alice"].DIDAW, false)
			if err != nil {
				t.Fatal(err)
			}
			adopted := adoptionSigned(t, parentID, map[string]any{"kind": "identity", "id": v.Keys["alice"].DIDAW}, v.key(t, "alice"))
			response, err := awid.EncodeIDCertificateResponse(request.RequestID, adoptionChain(v.Certificates["alice"].Signed, adopted))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executeIDParentImport(t.Context(), parentOpts, response); err != nil {
				t.Fatal(err)
			}
			assertWho("no_human")
			childOpts := idParentOptions{IdentityHome: childHome, WorkingDir: filepath.Dir(childHome), Domain: "example.com", RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: resolver}
			refresh, raw, err := executeIDParentResign(childOpts)
			if err != nil {
				t.Fatal(err)
			}
			issuerOpts := idChildOptions{IdentityHome: parentHome, WorkingDir: filepath.Dir(parentHome), RegistryURL: server.URL, TXTResolver: resolver, HTTPClient: server.Client(), Now: time.Now}
			if scenario == "unrecorded" {
				if err := os.RemoveAll(issuance.Dir); err != nil {
					t.Fatal(err)
				}
				if _, err := executeIDChildReceive(t.Context(), issuerOpts, raw); awid.IDCertificateErrorCode(err) != "issuance_not_recorded" {
					t.Fatalf("unrecorded refresh: %v", err)
				}
				assertWho("no_human")
				return
			}
			if _, err := executeIDChildReceive(t.Context(), issuerOpts, raw); err != nil {
				t.Fatal(err)
			}
			if scenario == "revoked-parent" {
				statusName = "alice-revoked-now"
			}
			refreshed, err := executeIDChildApprove(t.Context(), issuerOpts, refresh.RequestID)
			if scenario == "revoked-parent" {
				if err == nil {
					t.Fatal("revoked ancestor signed refresh")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executeIDParentImport(t.Context(), childOpts, refreshed); err != nil {
				t.Fatal(err)
			}
			assertWho("nearest_human")
		})
	}
}

func TestParentRefreshUpdatesRegisteredAncestorWithoutChangingLocalChild(t *testing.T) {
	for _, scenario := range []string{"local-child", "registered-subject", "unavailable", "no-registered-ancestor"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AW_CONFIG_PATH", "")
			v := adoptionVectors(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "unavailable" {
					http.Error(w, "unavailable", 503)
					return
				}
				json.NewEncoder(w).Encode(v.Statuses["normal"])
			}))
			defer server.Close()
			t.Setenv("AWID_REGISTRY_URL", server.URL)
			parentID := v.Keys["global_agent"].DIDAW
			childID := v.Keys["root_agent"].DIDKey
			child := adoptionSigned(t, childID, map[string]any{"kind": "identity", "id": parentID}, v.key(t, "global_agent"))
			chain := adoptionChain(v.Certificates["registered-root-agent"].Signed, child)
			global := scenario == "registered-subject"
			if global {
				chain = adoptionChain(v.Certificates["registered-root-agent"].Signed)
				childID = parentID
			}
			if scenario == "no-registered-ancestor" {
				chain = adoptionChain(v.Certificates["root-agent"].Signed)
			}
			home := adoptionHome(t, v, global, chain)
			before, err := awconfig.LoadInstalledIDChain(home)
			if err != nil {
				t.Fatal(err)
			}
			opts := idParentOptions{IdentityHome: home, WorkingDir: filepath.Dir(home), Domain: "example.com", RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}}}
			// Existing resign is deliberately unavailable for registered subjects.
			if global {
				if _, _, err := executeIDParentResign(opts); err == nil {
					t.Fatal("registered subject was re-signed")
				}
			}
			verdict, err := executeIDParentRefresh(t.Context(), opts)
			if scenario == "unavailable" || scenario == "no-registered-ancestor" {
				if err == nil {
					t.Fatal("unavailable ancestry refreshed")
				}
				after, _ := awconfig.LoadInstalledIDChain(home)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("failed refresh changed chain")
				}
				return
			}
			if err != nil || verdict.Outcome != "nearest_human" || verdict.HumanID == nil || *verdict.HumanID != v.Keys["alice"].DIDAW {
				t.Fatalf("refresh: %+v %v", verdict, err)
			}
			after, err := awconfig.LoadInstalledIDChain(home)
			if err != nil {
				t.Fatal(err)
			}
			certs := after.Bundle["certificates"].([]any)
			leaf := certs[len(certs)-1].(map[string]any)
			if leaf["certificate"].(map[string]any)["id"] != childID {
				t.Fatal("refresh changed subject")
			}
			if !global {
				oldLeaf := before.Bundle["certificates"].([]any)[1]
				if !reflect.DeepEqual(oldLeaf, leaf) {
					t.Fatal("refresh re-signed local child")
				}
			}
		})
	}
}

func TestLocalCrossDomainAdoptionAndChildrenBeforeAndAfter(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	v := adoptionVectors(t)
	oldDomain := "legacy.example.com"
	newDomain := "example.com"
	oldStatus := map[string]any{"v": 1, "domain": oldDomain, "observed_at": v.Statuses["normal"]["observed_at"], "namespace": v.Statuses["normal"]["namespace"], "identities": []any{}, "missing": []any{}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		status := v.Statuses["normal"]
		if request["domain"] == oldDomain {
			status = oldStatus
		}
		json.NewEncoder(w).Encode(status)
	}))
	defer server.Close()
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	resolver := staticTXTResolver{"_awid." + oldDomain: {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}, "_awid." + newDomain: {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}}
	registry := awid.NewAWIDRegistryClient(server.Client(), resolver)
	registry.DefaultRegistryURL = server.URL
	parentID := v.Keys["root_agent"].DIDKey
	childID := v.Keys["coordinator"].DIDKey
	oldRoot := adoptionSignedInDomain(t, parentID, map[string]any{"kind": "namespace", "id": oldDomain}, v.key(t, "root"), oldDomain)
	oldChain := adoptionChain(oldRoot)
	parentHome := adoptionHome(t, v, false, oldChain)
	issuance := awconfig.IDIssuanceFileStore{Dir: awconfig.IdentityIssuanceDir(parentHome)}
	who := func(chain map[string]any, id, domain, want string) {
		t.Helper()
		subject := awid.IDChainSubject{ID: id, DIDKey: id}
		evidence := idStatusAt(registry, resolver, server.URL).IDChainEvidence(t.Context(), chain, subject, domain)
		result := awid.VerifyIDChain(chain, subject, evidence, domain)
		if result.Outcome != want || result.IdentityValid == nil || !*result.IdentityValid {
			t.Fatalf("who in %s: %+v", domain, result)
		}
		if want == "nearest_human" && (result.HumanID == nil || *result.HumanID != v.Keys["alice"].DIDAW) {
			t.Fatal("wrong nearest human")
		}

	}
	spawn := func(chain map[string]any, id, domain string) map[string]any {
		t.Helper()
		subject := awid.IDChainSubject{ID: parentID, DIDKey: parentID}
		evidence := idStatusAt(registry, resolver, server.URL).IDChainEvidence(t.Context(), chain, subject, domain)
		out, err := awid.IssueIDChild(issuance, awid.IDChild{ID: id, Domain: domain, Parent: map[string]any{"kind": "identity", "id": parentID}, Kind: "agent"}, chain["certificates"].([]any), evidence, awid.KeySigner(v.key(t, "root_agent")), time.Date(2026, 10, 26, 0, 21, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	childChain := spawn(oldChain, childID, oldDomain)
	who(childChain, childID, oldDomain, "no_human")
	childHome := filepath.Join(t.TempDir(), ".aw")
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(childHome, "identity.yaml"), &awconfig.WorktreeIdentity{DID: childID, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(childHome, "signing.key"), v.key(t, "coordinator")); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveInstalledIDChain(childHome, childChain); err != nil {
		t.Fatal(err)
	}
	opts := idParentOptions{IdentityHome: parentHome, WorkingDir: filepath.Dir(parentHome), Domain: newDomain, RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: resolver}
	request, _, err := executeIDParentRequest(opts, "11111111-1111-4111-8111-111111111111", v.Keys["alice"].DIDAW, false)
	if err != nil {
		t.Fatal(err)
	}
	adopted := adoptionSigned(t, parentID, map[string]any{"kind": "identity", "id": v.Keys["alice"].DIDAW}, v.key(t, "alice"))
	newChain := adoptionChain(v.Certificates["alice"].Signed, adopted)
	response, err := awid.EncodeIDCertificateResponse(request.RequestID, newChain)
	if err != nil {
		t.Fatal(err)
	}
	importOpts := opts
	importOpts.Domain = ""
	if _, err := executeIDParentImport(t.Context(), importOpts, response); err != nil {
		t.Fatal(err)
	}
	installed, err := awconfig.LoadInstalledIDChain(parentHome)
	if err != nil {
		t.Fatal(err)
	}
	who(installed.Bundle, parentID, newDomain, "nearest_human")
	if _, _, err := executeIDParentRequest(opts, "22222222-2222-4222-8222-222222222222", v.Keys["bob"].DIDAW, false); err == nil {
		t.Fatal("second adoption allowed")
	}
	// The child's carried old-domain chain remains independently valid.
	who(childChain, childID, oldDomain, "no_human")
	childOpts := idParentOptions{IdentityHome: childHome, WorkingDir: filepath.Dir(childHome), RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: resolver}
	refresh, raw, err := executeIDParentResign(childOpts)
	if err != nil {
		t.Fatal(err)
	}
	issuerOpts := idChildOptions{IdentityHome: parentHome, WorkingDir: filepath.Dir(parentHome), RegistryURL: server.URL, HTTPClient: server.Client(), TXTResolver: resolver, Now: time.Now}
	if _, err := executeIDChildReceive(t.Context(), issuerOpts, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := executeIDChildApprove(t.Context(), issuerOpts, refresh.RequestID); err == nil || !strings.Contains(err.Error(), "respawn under the adopted parent") {
		t.Fatalf("cross-domain child refresh: %v", err)
	}
	if _, err := awid.ApproveIDResignRequest(issuance, refresh.RequestID, parentID, newChain["certificates"].([]any), nil, newDomain, func([]byte) (string, []byte, error) {
		t.Fatal("cross-domain re-sign reached signer")
		return "", nil, nil
	}, time.Now()); err == nil || !strings.Contains(err.Error(), "respawn under the adopted parent") {
		t.Fatalf("SDK cross-domain refresh: %v", err)
	}
	still, err := awconfig.LoadInstalledIDChain(childHome)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := awid.CanonicalJSONValue(still.Bundle)
	b, _ := awid.CanonicalJSONValue(childChain)
	if a != b {
		t.Fatal("refused refresh changed child chain")
	}
	who(still.Bundle, childID, oldDomain, "no_human")
	afterID := v.Keys["seat"].DIDKey
	after := spawn(newChain, afterID, newDomain)
	who(after, afterID, newDomain, "nearest_human")
}
