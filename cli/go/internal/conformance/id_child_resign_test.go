package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	awid "github.com/awebai/aw/awid"
)

type idChildExchangeCase struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Input  struct {
		Request               string   `json:"request"`
		Response              string   `json:"response"`
		ParentStatus          string   `json:"parent_status"`
		ParentStatusAfterWait string   `json:"parent_status_after_wait"`
		IssuedCertificateIDs  []string `json:"issued_certificate_ids"`
		IssuedAt              string   `json:"issued_at"`
	} `json:"input"`
	Expected struct {
		Accepted             bool   `json:"accepted"`
		Reason               string `json:"reason"`
		Response             string `json:"response"`
		ParentSignatures     *int   `json:"parent_signatures"`
		InstalledCertificate string `json:"installed_certificate"`
		IDRegistration       string `json:"id_registration"`
	} `json:"expected"`
}

type idChildExchange struct {
	v        idResignVectors
	requests map[string]struct {
		Signed        map[string]any `json:"signed"`
		CanonicalUTF8 string         `json:"canonical_utf8"`
	}
	responses map[string]struct {
		CanonicalUTF8 string `json:"canonical_utf8"`
	}
	cases map[string]idChildExchangeCase
}

func loadIDChildExchange(t *testing.T) idChildExchange {
	t.Helper()
	var raw struct {
		ChildRequests struct {
			Requests map[string]struct {
				Signed        map[string]any `json:"signed"`
				CanonicalUTF8 string         `json:"canonical_utf8"`
			} `json:"requests"`
			Responses map[string]struct {
				CanonicalUTF8 string `json:"canonical_utf8"`
			} `json:"responses"`
		} `json:"child_requests"`
		Cases []json.RawMessage `json:"operation_cases"`
	}
	d := json.NewDecoder(bytes.NewReader(readRootVector(t, "id-certificates-v1.json")))
	d.UseNumber()
	if err := d.Decode(&raw); err != nil {
		t.Fatal(err)
	}
	x := idChildExchange{v: loadIDResignVectors(t), requests: raw.ChildRequests.Requests, responses: raw.ChildRequests.Responses, cases: map[string]idChildExchangeCase{}}
	for _, item := range raw.Cases {
		var named struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(item, &named); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(named.Name, "csr-") {
			continue
		}
		var c idChildExchangeCase
		if err := json.Unmarshal(item, &c); err != nil {
			t.Fatalf("%s: %v", named.Name, err)
		}
		x.cases[c.Name] = c
	}
	return x
}

// parentChain is the parent's own current chain as its status row records it.
func (x idChildExchange) parentChain(t *testing.T, status, parent string) []any {
	t.Helper()
	for _, row := range x.v.Statuses[status]["identities"].([]any) {
		r := row.(map[string]any)
		if r["id"] == parent {
			revisions := r["certificates"].([]any)
			return []any{revisions[len(revisions)-1].(map[string]any)["signed"]}
		}
	}
	t.Fatalf("no row for %s in %s", parent, status)
	return nil
}

func (x idChildExchange) evidence(status string) *awid.IDChainEvidence {
	f := resignFixture{status: x.v.Statuses[status]}
	return f.evidence(0)
}

type approval struct {
	x        idChildExchange
	store    *issuedStore
	request  string
	status   string
	signer   string
	now      time.Time
	calls    int
	parentID string
}

func (x idChildExchange) approval(t *testing.T, c idChildExchangeCase) *approval {
	t.Helper()
	now, err := time.Parse(time.RFC3339, c.Input.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	status := c.Input.ParentStatus
	if c.Input.ParentStatusAfterWait != "" {
		// The evidence that reaches the locked signing step is the one after the wait.
		status = c.Input.ParentStatusAfterWait
	}
	return &approval{x: x, store: newIssuedStore(t, x.v, c.Input.IssuedCertificateIDs...), request: x.requests[c.Input.Request].CanonicalUTF8, status: status, signer: "alice_rotated", now: now, parentID: x.v.Keys["alice"].DIDAW}
}

func (a *approval) receive() (*awid.IDIssuanceEntry, error) {
	return awid.ReceiveIDResignRequest(a.store, []byte(a.request))
}

func (a *approval) approve(t *testing.T) ([]byte, error) {
	t.Helper()
	parsed, err := awid.ParseIDCertificateRequest([]byte(a.request))
	if err != nil {
		t.Fatal(err)
	}
	requestID := parsed["request"].(map[string]any)["request_id"].(string)
	return awid.ApproveIDResignRequest(a.store, requestID, a.parentID, a.x.parentChain(t, "alice-rotated", a.parentID), a.x.evidence(a.status), "example.com", vectorSigner(t, a.x.v, a.signer, &a.calls), a.now)
}

func TestIDChildResignExchangeFrozenCases(t *testing.T) {
	x := loadIDChildExchange(t)
	for _, name := range []string{"csr-local-resign-contact-no-human-login", "csr-local-resign-without-provenance-refuses", "csr-local-resign-substituted-parent-refuses", "csr-local-resign-parent-revoked-after-wait"} {
		c, ok := x.cases[name]
		if !ok {
			t.Fatalf("missing frozen case %s", name)
		}
		t.Run(name, func(t *testing.T) {
			a := x.approval(t, c)
			var response []byte
			_, err := a.receive()
			if err == nil {
				response, err = a.approve(t)
			}
			if a.calls != *c.Expected.ParentSignatures {
				t.Fatalf("signer calls=%d want %d", a.calls, *c.Expected.ParentSignatures)
			}
			if !c.Expected.Accepted {
				if got := awid.IDCertificateErrorCode(err); got != c.Expected.Reason || response != nil {
					t.Fatalf("reason=%q (%v) want %q", got, err, c.Expected.Reason)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(response) != x.responses[c.Expected.Response].CanonicalUTF8 {
				t.Fatalf("response differs from frozen %s:\n%s", c.Expected.Response, response)
			}
			if !a.store.has(x.v.Certificates["coordinator-resigned"].CertificateID) {
				t.Fatal("the issued certificate was not recorded before output")
			}
		})
	}
}

func TestIDChildResignExchangeProbes(t *testing.T) {
	x := loadIDChildExchange(t)
	accepted := x.cases["csr-local-resign-contact-no-human-login"]
	frozen := x.responses["local-resigned"].CanonicalUTF8
	newID := x.v.Certificates["coordinator-resigned"].CertificateID
	oldID := x.v.Certificates["coordinator"].CertificateID

	t.Run("the old entry records the exact response before the new entry", func(t *testing.T) {
		a := x.approval(t, accepted)
		if _, err := a.receive(); err != nil {
			t.Fatal(err)
		}
		a.store.failWrite = a.store.writes + 2
		if _, err := a.approve(t); err == nil {
			t.Fatal("approve reported success although the new entry was not written")
		}
		old, _ := a.store.Entry(oldID)
		if old.Resign == nil || old.Resign.State != "issued" || old.Resign.Response != frozen || old.Resign.NewCertificateID != newID || a.store.has(newID) {
			t.Fatalf("crash state: %+v new=%v", old.Resign, a.store.has(newID))
		}
		response, err := a.approve(t)
		if err != nil || string(response) != frozen || a.calls != 1 || !a.store.has(newID) {
			t.Fatalf("retry after the crash: err=%v calls=%d new=%v", err, a.calls, a.store.has(newID))
		}
	})
	t.Run("a crash before the old entry is updated leaves the request pending and unsigned", func(t *testing.T) {
		a := x.approval(t, accepted)
		if _, err := a.receive(); err != nil {
			t.Fatal(err)
		}
		a.store.failWrite = a.store.writes + 1
		if _, err := a.approve(t); err == nil {
			t.Fatal("approve reported success without recording")
		}
		old, _ := a.store.Entry(oldID)
		if old.Resign.State != "pending" || a.store.has(newID) {
			t.Fatalf("state=%s new=%v", old.Resign.State, a.store.has(newID))
		}
	})
	t.Run("byte-identical retries return the stored response without signing", func(t *testing.T) {
		a := x.approval(t, accepted)
		for i := 0; i < 2; i++ {
			if _, err := a.receive(); err != nil {
				t.Fatal(err)
			}
		}
		first, err := a.approve(t)
		if err != nil {
			t.Fatal(err)
		}
		a.now = a.now.Add(time.Hour)
		second, err := a.approve(t)
		if err != nil || !bytes.Equal(first, second) || a.calls != 1 {
			t.Fatalf("retry: err=%v same=%v calls=%d", err, bytes.Equal(first, second), a.calls)
		}
		if _, err := a.receive(); err != nil {
			t.Fatalf("byte-identical receive after issue: %v", err)
		}
	})
	t.Run("a lost response is re-exported from the store", func(t *testing.T) {
		a := x.approval(t, accepted)
		if _, err := a.receive(); err != nil {
			t.Fatal(err)
		}
		if _, err := a.approve(t); err != nil {
			t.Fatal(err)
		}
		response, err := awid.IDResignResponse(a.store, "20000000-0000-4000-8000-000000000004")
		if err != nil || string(response) != frozen || a.calls != 1 {
			t.Fatalf("re-export: err=%v calls=%d", err, a.calls)
		}
	})
	t.Run("a pending request has no response to re-export", func(t *testing.T) {
		a := x.approval(t, accepted)
		if _, err := a.receive(); err != nil {
			t.Fatal(err)
		}
		if response, err := awid.IDResignResponse(a.store, "20000000-0000-4000-8000-000000000004"); err == nil || response != nil {
			t.Fatal("re-exported a response for a pending request")
		}
	})
	t.Run("one re-sign per old entry", func(t *testing.T) {
		for _, state := range []string{"pending", "issued"} {
			t.Run(state, func(t *testing.T) {
				a := x.approval(t, accepted)
				if _, err := a.receive(); err != nil {
					t.Fatal(err)
				}
				if state == "issued" {
					if _, err := a.approve(t); err != nil {
						t.Fatal(err)
					}
				}
				writes := a.store.writes
				// The same old certificate under another request ID.
				a.request = x.requests["local-resign-substituted-parent"].CanonicalUTF8
				_, err := a.receive()
				if got := awid.IDCertificateErrorCode(err); got != "request_conflict" || a.store.writes != writes {
					t.Fatalf("reason=%q (%v) writes=%d", got, err, a.store.writes-writes)
				}
			})
		}
	})
	t.Run("a request id already attached to another certificate", func(t *testing.T) {
		a := x.approval(t, accepted)
		if _, err := a.receive(); err != nil {
			t.Fatal(err)
		}
		// Another recorded certificate of the same child, re-signed under the same request ID.
		other := map[string]any{}
		for k, v := range x.v.Certificates["coordinator"].Signed["certificate"].(map[string]any) {
			other[k] = v
		}
		other["issued_at"] = "2026-10-26T00:05:00Z"
		otherSigned := signWith(t, x.v, "alice", other)
		otherID, err := awid.IDCertificateID(other)
		if err != nil {
			t.Fatal(err)
		}
		a.store.seed(t, otherID, otherSigned)
		request := map[string]any{}
		for k, v := range x.requests["local-resign"].Signed["request"].(map[string]any) {
			request[k] = v
		}
		request["old_certificate"] = otherSigned
		a.request = signRequest(t, x.v, "coordinator", request)
		writes := a.store.writes
		if _, err := a.receive(); awid.IDCertificateErrorCode(err) != "request_conflict" || a.store.writes != writes {
			t.Fatalf("receive: %v writes=%d", err, a.store.writes-writes)
		}
	})
	t.Run("approve needs the parent's own chain", func(t *testing.T) {
		a := x.approval(t, accepted)
		if _, err := a.receive(); err != nil {
			t.Fatal(err)
		}
		bob := x.parentChain(t, "alice-rotated", x.v.Keys["bob"].DIDAW)
		_, err := awid.ApproveIDResignRequest(a.store, "20000000-0000-4000-8000-000000000004", a.parentID, bob, x.evidence("alice-rotated"), "example.com", vectorSigner(t, x.v, a.signer, &a.calls), a.now)
		if err == nil || a.calls != 0 || a.store.has(newID) {
			t.Fatalf("approve with another identity's chain: err=%v calls=%d", err, a.calls)
		}
	})
	t.Run("a refused request issues nothing and frees the old entry", func(t *testing.T) {
		a := x.approval(t, accepted)
		if _, err := a.receive(); err != nil {
			t.Fatal(err)
		}
		if err := awid.RefuseIDResignRequest(a.store, "20000000-0000-4000-8000-000000000004"); err != nil {
			t.Fatal(err)
		}
		old, _ := a.store.Entry(oldID)
		if old.Resign.State != "failed" || a.calls != 0 {
			t.Fatalf("state=%s calls=%d", old.Resign.State, a.calls)
		}
		if _, err := a.approve(t); err == nil || a.calls != 0 {
			t.Fatalf("approve after refuse: %v calls=%d", err, a.calls)
		}
	})
	t.Run("an issued request cannot be refused", func(t *testing.T) {
		a := x.approval(t, accepted)
		if _, err := a.receive(); err != nil {
			t.Fatal(err)
		}
		if _, err := a.approve(t); err != nil {
			t.Fatal(err)
		}
		if err := awid.RefuseIDResignRequest(a.store, "20000000-0000-4000-8000-000000000004"); err == nil {
			t.Fatal("an issued request was refused")
		}
		old, _ := a.store.Entry(oldID)
		if old.Resign.State != "issued" {
			t.Fatalf("state=%s", old.Resign.State)
		}
	})
	t.Run("receive for an unrecorded old certificate writes nothing", func(t *testing.T) {
		a := x.approval(t, accepted)
		a.store = newIssuedStore(t, x.v)
		if _, err := a.receive(); awid.IDCertificateErrorCode(err) != "issuance_not_recorded" || a.store.writes != 0 {
			t.Fatalf("receive: %v writes=%d", err, a.store.writes)
		}
	})
	t.Run("receive refuses an issue request on the re-sign path", func(t *testing.T) {
		a := x.approval(t, accepted)
		a.request = x.requests["human-issue"].CanonicalUTF8
		if _, err := a.receive(); awid.IDCertificateErrorCode(err) != "invalid_shape" || a.store.writes != 0 {
			t.Fatalf("receive: %v writes=%d", err, a.store.writes)
		}
	})
}

func TestIDChildImportFrozenCases(t *testing.T) {
	x := loadIDChildExchange(t)
	for _, name := range []string{"csr-import-mismatch-preserves-old-certificate", "csr-local-import-matching-response", "csr-human-import-remains-pending"} {
		c, ok := x.cases[name]
		if !ok {
			t.Fatalf("missing frozen case %s", name)
		}
		t.Run(name, func(t *testing.T) {
			status := c.Input.ParentStatus
			if status == "" {
				status = "alice-rotated"
			}
			imported, err := awid.ImportIDCertificateResponse(x.requests[c.Input.Request].Signed, []byte(x.responses[c.Input.Response].CanonicalUTF8), x.evidence(status), "example.com")
			if !c.Expected.Accepted {
				if got := awid.IDCertificateErrorCode(err); got != c.Expected.Reason || imported != nil {
					t.Fatalf("reason=%q (%v) want %q", got, err, c.Expected.Reason)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Expected.InstalledCertificate != "" && !reflect.DeepEqual(imported.Certificate, x.v.Certificates[c.Expected.InstalledCertificate].Signed) {
				t.Fatal("imported certificate is not the frozen one")
			}
			wantPending := c.Expected.IDRegistration == "pending"
			if imported.RegistrationPending != wantPending {
				t.Fatalf("registration pending=%v want %v", imported.RegistrationPending, wantPending)
			}
		})
	}
}

func TestIDChildImportProbes(t *testing.T) {
	x := loadIDChildExchange(t)
	request := x.requests["local-resign"].Signed
	good := x.responses["local-resigned"].CanonicalUTF8
	refuses := func(t *testing.T, raw string, status, reason string) {
		t.Helper()
		imported, err := awid.ImportIDCertificateResponse(request, []byte(raw), x.evidence(status), "example.com")
		if got := awid.IDCertificateErrorCode(err); got != reason || imported != nil {
			t.Fatalf("reason=%q (%v) want %q", got, err, reason)
		}
	}
	t.Run("tampered leaf signature", func(t *testing.T) {
		leafSig := x.v.Certificates["coordinator-resigned"].Signed["signature"].(string)
		tampered := []byte(leafSig)
		if tampered[0] == 'A' {
			tampered[0] = 'B'
		} else {
			tampered[0] = 'A'
		}
		refuses(t, strings.Replace(good, leafSig, string(tampered), 1), "alice-rotated", "invalid_signature")
	})
	t.Run("leaf signed by the parent's retired key", func(t *testing.T) {
		old := x.v.Certificates["coordinator"].Signed
		chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": append(x.parentChain(t, "alice-rotated", x.v.Keys["alice"].DIDAW), old)}
		raw, err := awid.EncodeIDCertificateResponse("20000000-0000-4000-8000-000000000004", chain)
		if err != nil {
			t.Fatal(err)
		}
		refuses(t, string(raw), "alice-rotated", "stale_issuer_key")
	})
	t.Run("response for another request id", func(t *testing.T) {
		refuses(t, strings.Replace(good, "20000000-0000-4000-8000-000000000004", "20000000-0000-4000-8000-000000000009", 1), "alice-rotated", "request_binding_mismatch")
	})
	t.Run("leaf for another id under the same request id", func(t *testing.T) {
		outstanding := map[string]any{}
		for k, v := range request["request"].(map[string]any) {
			outstanding[k] = v
		}
		outstanding["id"] = x.v.Keys["seat"].DIDKey
		imported, err := awid.ImportIDCertificateResponse(map[string]any{"request": outstanding, "signature": request["signature"]}, []byte(good), x.evidence("alice-rotated"), "example.com")
		if awid.IDCertificateErrorCode(err) != "request_binding_mismatch" || imported != nil {
			t.Fatalf("binding: %v", err)
		}
	})
	t.Run("parent revoked", func(t *testing.T) {
		refuses(t, good, "alice-revoked-now", "revoked")
	})
	t.Run("stale parent evidence", func(t *testing.T) {
		f := resignFixture{status: x.v.Statuses["alice-rotated"]}
		imported, err := awid.ImportIDCertificateResponse(request, []byte(good), f.evidence(61), "example.com")
		if awid.IDCertificateErrorCode(err) != "evidence_unavailable" || imported != nil {
			t.Fatalf("stale evidence: %v", err)
		}
	})
}

func signRequest(t *testing.T, v idResignVectors, key string, request map[string]any) string {
	t.Helper()
	seed, err := hex.DecodeString(v.Keys[key].SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := awid.IDCertificateRequestSigningBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := awid.CanonicalJSONValue(map[string]any{"request": request, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), payload))})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The frozen accepted exchange on the durable file store, including a retry
// after the new entry's write was lost.
func TestIDChildResignExchangeOnTheFileStore(t *testing.T) {
	x := loadIDChildExchange(t)
	c := x.cases["csr-local-resign-contact-no-human-login"]
	a := x.approval(t, c)
	dir := filepath.Join(t.TempDir(), "id-issuance")
	store := awconfig.IDIssuanceFileStore{Dir: dir}
	oldID := x.v.Certificates["coordinator"].CertificateID
	if err := store.Put(&awid.IDIssuanceEntry{CertificateID: oldID, Signed: x.v.Certificates["coordinator"].Signed}); err != nil {
		t.Fatal(err)
	}
	parsed, err := awid.ParseIDCertificateRequest([]byte(a.request))
	if err != nil {
		t.Fatal(err)
	}
	requestID := parsed["request"].(map[string]any)["request_id"].(string)
	if _, err := awid.ReceiveIDResignRequest(store, []byte(a.request)); err != nil {
		t.Fatal(err)
	}
	approve := func() ([]byte, error) {
		return awid.ApproveIDResignRequest(store, requestID, a.parentID, x.parentChain(t, "alice-rotated", a.parentID), x.evidence(a.status), "example.com", vectorSigner(t, x.v, a.signer, &a.calls), a.now)
	}
	response, err := approve()
	if err != nil || string(response) != x.responses["local-resigned"].CanonicalUTF8 {
		t.Fatalf("approve: %v", err)
	}
	newID := x.v.Certificates["coordinator-resigned"].CertificateID
	newPath := filepath.Join(dir, strings.TrimPrefix(newID, "sha256:")+".json")
	if err := os.Remove(newPath); err != nil {
		t.Fatal(err)
	}
	again, err := approve()
	if err != nil || !bytes.Equal(again, response) || a.calls != 1 {
		t.Fatalf("retry: err=%v calls=%d", err, a.calls)
	}
	if entry, err := store.Entry(newID); err != nil || entry == nil {
		t.Fatalf("the lost entry was not recreated: %v", err)
	}
}
