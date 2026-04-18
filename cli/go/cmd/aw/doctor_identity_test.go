package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type doctorIdentityFixture struct {
	Bin        string
	Dir        string
	DID        string
	StableID   string
	Address    string
	Domain     string
	Handle     string
	SigningKey ed25519.PrivateKey
}

func writeDoctorIdentityFixture(t *testing.T, registryURL string) doctorIdentityFixture {
	t.Helper()
	bin, tmp := buildDoctorBinary(t)
	priv := writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath()))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	identity.RegistryURL = registryURL
	writeIdentityForTest(t, tmp, *identity)
	domain, handle, _ := awconfig.CutIdentityAddress(identity.Address)
	return doctorIdentityFixture{
		Bin:        bin,
		Dir:        tmp,
		DID:        identity.DID,
		StableID:   identity.StableID,
		Address:    identity.Address,
		Domain:     domain,
		Handle:     handle,
		SigningKey: priv,
	}
}

func updateDoctorIdentityRegistryURL(t *testing.T, workingDir, registryURL string) {
	t.Helper()
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	identity.RegistryURL = registryURL
	writeIdentityForTest(t, workingDir, *identity)
}

func newDoctorAWIDServer(t *testing.T, fixture *doctorIdentityFixture, opts map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/v1/did/" + fixture.StableID + "/key":
			switch opts["did"] {
			case "not_found":
				http.NotFound(w, r)
			case "unavailable":
				http.Error(w, `{"detail":"registry token should not leak"}`, http.StatusInternalServerError)
			default:
				current := fixture.DID
				if opts["current_key"] == "mismatch" {
					wrongPub, _, err := awid.GenerateKeypair()
					if err != nil {
						t.Fatal(err)
					}
					current = awid.ComputeDIDKey(wrongPub)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"did_aw":          fixture.StableID,
					"current_did_key": current,
				})
			}
		case "/v1/did/" + fixture.StableID + "/log":
			if opts["log"] == "unavailable" {
				http.Error(w, "temporary outage", http.StatusInternalServerError)
				return
			}
			if opts["log"] == "broken" {
				_ = json.NewEncoder(w).Encode([]map[string]any{{"seq": 1}})
				return
			}
			logEntry := testDidLogEntry(t, fixture.StableID, fixture.SigningKey, fixture.DID, "create", nil, nil, 1, strings.Repeat("a", 64))
			_ = json.NewEncoder(w).Encode([]map[string]any{didLogJSON(logEntry)})
		case "/v1/namespaces/" + fixture.Domain + "/addresses/" + fixture.Handle:
			switch opts["address"] {
			case "not_found":
				http.NotFound(w, r)
			case "forbidden":
				http.Error(w, "hidden token should not leak", http.StatusForbidden)
			default:
				didAW := fixture.StableID
				if opts["address"] == "different_stable" {
					didAW = "did:aw:DifferentStable"
				}
				current := fixture.DID
				if opts["address_current"] == "mismatch" {
					wrongPub, _, err := awid.GenerateKeypair()
					if err != nil {
						t.Fatal(err)
					}
					current = awid.ComputeDIDKey(wrongPub)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"address_id":      "addr-1",
					"domain":          fixture.Domain,
					"name":            fixture.Handle,
					"did_aw":          didAW,
					"current_did_key": current,
					"reachability":    "public",
					"created_at":      "2026-04-04T00:00:00Z",
				})
			}
		case "/v1/namespaces/" + fixture.Domain + "/addresses":
			switch opts["list"] {
			case "forbidden":
				http.Error(w, "hidden token should not leak", http.StatusForbidden)
			case "empty":
				_ = json.NewEncoder(w).Encode(map[string]any{"addresses": []any{}})
			case "different_address":
				_ = json.NewEncoder(w).Encode(map[string]any{"addresses": []map[string]any{{
					"address_id":      "addr-2",
					"domain":          fixture.Domain,
					"name":            "other",
					"did_aw":          fixture.StableID,
					"current_did_key": fixture.DID,
					"reachability":    "public",
					"created_at":      "2026-04-04T00:00:00Z",
				}}})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"addresses": []map[string]any{{
					"address_id":      "addr-1",
					"domain":          fixture.Domain,
					"name":            fixture.Handle,
					"did_aw":          fixture.StableID,
					"current_did_key": fixture.DID,
					"reachability":    "public",
					"created_at":      "2026-04-04T00:00:00Z",
				}}})
			}
		default:
			t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func TestAwDoctorIdentityOfflineDoesNotContactAWID(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "should not be called", http.StatusTeapot)
	}))
	t.Cleanup(server.Close)
	fixture := writeDoctorIdentityFixture(t, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--offline", "--json")
	if err != nil {
		t.Fatalf("doctor registry offline failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusUnknown)
	if check.Detail["reason"] != "offline_mode" {
		t.Fatalf("offline reason=%v", check.Detail["reason"])
	}
	if hits.Load() != 0 {
		t.Fatalf("offline contacted awid %d times", hits.Load())
	}
}

func TestAwDoctorIdentityAutoDoesNotContactAWID(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "should not be called", http.StatusTeapot)
	}))
	t.Cleanup(server.Close)
	fixture := writeDoctorIdentityFixture(t, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--json")
	if err != nil {
		t.Fatalf("doctor registry auto failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusUnknown)
	if check.Detail["reason"] != "auto_mode" {
		t.Fatalf("auto reason=%v", check.Detail["reason"])
	}
	if hits.Load() != 0 {
		t.Fatalf("auto contacted awid %d times", hits.Load())
	}
}

func TestAwDoctorIdentityPersistentHappyPath(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, nil)
	updateDoctorIdentityRegistryURL(t, fixture.Dir, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	for _, id := range []string{
		doctorCheckAWIDDIDResolve,
		doctorCheckAWIDDIDCurrentKey,
		doctorCheckAWIDDIDLog,
		doctorCheckAWIDAddressResolve,
		doctorCheckAWIDAddressStableID,
		doctorCheckAWIDAddressCurrentKey,
		doctorCheckAWIDAddressReverseListing,
	} {
		requireDoctorCheckStatus(t, got, id, doctorStatusOK)
	}
}

func TestAwDoctorIdentityEphemeralSkipsPublicRegistry(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "should not be called", http.StatusTeapot)
	}))
	t.Cleanup(server.Close)

	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "identity", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor identity online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityLocalEphemeralAWID, doctorStatusOK)
	if hits.Load() != 0 {
		t.Fatalf("ephemeral identity contacted awid %d times", hits.Load())
	}

	out, err = runDoctorCLI(t, bin, tmp, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got = decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusInfo)
	if check.Detail["reason"] != "ephemeral_not_applicable" {
		t.Fatalf("ephemeral registry reason=%v", check.Detail["reason"])
	}
	if hits.Load() != 0 {
		t.Fatalf("ephemeral registry contacted awid %d times", hits.Load())
	}
}

func TestAwDoctorIdentityPersistentMissingIdentityYAMLFails(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	if err := os.Remove(filepath.Join(fixture.Dir, awconfig.DefaultWorktreeIdentityRelativePath())); err != nil {
		t.Fatalf("remove identity.yaml: %v", err)
	}

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "identity", "--json")
	if err != nil {
		t.Fatalf("doctor identity failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckIdentityLocalContext, doctorStatusFail)
	if check.Detail["expected_lifetime"] != awid.LifetimePersistent {
		t.Fatalf("expected_lifetime=%v", check.Detail["expected_lifetime"])
	}
	requireDoctorCheckStatus(t, got, doctorCheckIdentityLocalLifetime, doctorStatusOK)

	out, err = runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got = decodeDoctorOutput(t, out)
	registryCheck := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusBlocked)
	if registryCheck.Detail["reason"] != "missing_identity_context" {
		t.Fatalf("registry precondition reason=%v", registryCheck.Detail["reason"])
	}
}

func TestAwDoctorIdentityDIDNotFoundFails(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, map[string]string{"did": "not_found"})
	updateDoctorIdentityRegistryURL(t, fixture.Dir, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusFail)
	if check.Detail["reason"] != "did_not_found" {
		t.Fatalf("did_not_found reason=%v", check.Detail["reason"])
	}
	requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDCurrentKey, doctorStatusBlocked)
}

func TestAwDoctorIdentityAddressNotFoundWarns(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, map[string]string{"address": "not_found", "list": "empty"})
	updateDoctorIdentityRegistryURL(t, fixture.Dir, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressResolve, doctorStatusWarn)
	if check.Detail["reason"] != "address_not_found" {
		t.Fatalf("address_not_found reason=%v", check.Detail["reason"])
	}
	reverse := requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressReverseListing, doctorStatusWarn)
	if reverse.Detail["reason"] != "no_registered_address_for_did" {
		t.Fatalf("reverse reason=%v", reverse.Detail["reason"])
	}
}

func TestAwDoctorIdentityKeyMismatchFails(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, hits := newDoctorAWIDServer(t, &fixture, map[string]string{"current_key": "mismatch"})
	updateDoctorIdentityRegistryURL(t, fixture.Dir, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDCurrentKey, doctorStatusFail)
	logCheck := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDLog, doctorStatusBlocked)
	if logCheck.Detail["prerequisite"] != doctorCheckAWIDDIDCurrentKey {
		t.Fatalf("log prerequisite=%v", logCheck.Detail["prerequisite"])
	}
	addressCheck := requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressResolve, doctorStatusBlocked)
	if addressCheck.Detail["prerequisite"] != doctorCheckAWIDDIDCurrentKey {
		t.Fatalf("address prerequisite=%v", addressCheck.Detail["prerequisite"])
	}
	if hits.Load() != 1 {
		t.Fatalf("current-key mismatch made downstream awid requests: hits=%d", hits.Load())
	}
}

func TestAwDoctorIdentityAWIDUnavailableUnknown(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, map[string]string{"did": "unavailable"})
	updateDoctorIdentityRegistryURL(t, fixture.Dir, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusUnknown)
	if check.Detail["reason"] != "awid_unavailable" {
		t.Fatalf("unavailable reason=%v", check.Detail["reason"])
	}
}

func TestAwDoctorIdentityCallerLacksVisibility(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, hits := newDoctorAWIDServer(t, &fixture, map[string]string{"address": "forbidden"})
	updateDoctorIdentityRegistryURL(t, fixture.Dir, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressResolve, doctorStatusBlocked)
	if check.Detail["reason"] != "caller_lacks_visibility" {
		t.Fatalf("visibility reason=%v", check.Detail["reason"])
	}
	reverse := requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressReverseListing, doctorStatusBlocked)
	if reverse.Detail["reason"] != "caller_lacks_visibility" {
		t.Fatalf("reverse visibility reason=%v", reverse.Detail["reason"])
	}
	if hits.Load() != 3 {
		t.Fatalf("address 403 should not call reverse list endpoint: hits=%d", hits.Load())
	}
}

func TestAwDoctorIdentityAddressInconsistencyWarns(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, map[string]string{"address": "different_stable", "list": "different_address"})
	updateDoctorIdentityRegistryURL(t, fixture.Dir, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressStableID, doctorStatusWarn)
	requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressCurrentKey, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressReverseListing, doctorStatusWarn)
}

func TestAwDoctorIdentityNoPublicDiscoveryProof(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	updateDoctorIdentityRegistryURL(t, fixture.Dir, "")

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusBlocked)
	if check.Detail["reason"] != "no_explicit_registry_url" {
		t.Fatalf("registry precondition reason=%v", check.Detail["reason"])
	}
}

func TestAwDoctorIdentityOutputRedactsRegistrySecrets(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, map[string]string{"did": "unavailable"})
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	parsed.User = url.UserPassword("registry-user", "registry-pass")
	parsed.RawQuery = "token=secret-token"
	parsed.Fragment = "secret-fragment"
	updateDoctorIdentityRegistryURL(t, fixture.Dir, parsed.String())

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry online failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, secret := range []string{
		"registry-user",
		"registry-pass",
		"secret-token",
		"secret-fragment",
		"registry token should not leak",
		"Authorization",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("doctor registry output leaked %q:\n%s", secret, text)
		}
	}
	if !strings.Contains(text, server.URL) {
		t.Fatalf("doctor output did not include sanitized registry URL %s:\n%s", server.URL, text)
	}
}

func TestAwDoctorRootHasNoDuplicateCheckIDs(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, nil)
	updateDoctorIdentityRegistryURL(t, fixture.Dir, server.URL)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor root online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	seen := map[string]bool{}
	for _, check := range got.Checks {
		if seen[check.ID] {
			t.Fatalf("duplicate check id %s in %#v", check.ID, got.Checks)
		}
		seen[check.ID] = true
	}
}
