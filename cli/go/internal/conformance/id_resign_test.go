package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

type idResignCase struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Input  struct {
		OldCertificate       string         `json:"old_certificate"`
		ParentStatus         string         `json:"parent_status"`
		RequestedChange      map[string]any `json:"requested_change"`
		SubjectKeyProved     bool           `json:"subject_key_proved"`
		IssuedCertificateIDs []string       `json:"issued_certificate_ids"`
		IssuedAt             string         `json:"issued_at"`
	} `json:"input"`
	Expected struct {
		Accepted       bool   `json:"accepted"`
		Reason         string `json:"reason"`
		NewCertificate string `json:"new_certificate"`
		Writes         *int   `json:"writes"`
	} `json:"expected"`
}

type idResignVectors struct {
	Keys map[string]struct {
		SeedHex string `json:"seed_hex"`
		DIDKey  string `json:"did_key"`
		DIDAW   string `json:"did_aw"`
	} `json:"keys"`
	Certificates map[string]struct {
		Signed        map[string]any `json:"signed"`
		CertificateID string         `json:"certificate_id"`
	} `json:"certificates"`
	Statuses map[string]map[string]any `json:"status_fixtures"`
	Cases    []idResignCase            `json:"operation_cases"`
}

func loadIDResignVectors(t *testing.T) idResignVectors {
	t.Helper()
	var v idResignVectors
	d := json.NewDecoder(bytes.NewReader(readRootVector(t, "id-certificates-v1.json")))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// issuanceLog is an in-memory durable log: what the parent's signer issued.
type issuanceLog struct {
	ids    map[string]bool
	writes int
}

func newIssuanceLog(ids ...string) *issuanceLog {
	l := &issuanceLog{ids: map[string]bool{}}
	for _, id := range ids {
		l.ids[id] = true
	}
	return l
}
func (l *issuanceLog) Recorded(id string) (bool, error) { return l.ids[id], nil }
func (l *issuanceLog) Record(id string) error {
	l.ids[id] = true
	l.writes++
	return nil
}

func vectorSigner(t *testing.T, v idResignVectors, key string, calls *int) awid.IDCertificateSigner {
	t.Helper()
	seed, err := hex.DecodeString(v.Keys[key].SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	return func(payload []byte) (string, []byte, error) {
		*calls++
		return v.Keys[key].DIDKey, ed25519.Sign(private, payload), nil
	}
}

type resignFixture struct {
	v       idResignVectors
	request awid.IDResignRequest
	parent  string
	status  map[string]any
	log     *issuanceLog
	signer  string
	now     time.Time
}

func (f resignFixture) evidence(age float64) *awid.IDChainEvidence {
	domain := f.status["domain"].(string)
	epochs := f.status["namespace"].(map[string]any)["epochs"].([]any)
	current := epochs[len(epochs)-1].(map[string]any)["did_key"]
	authority := map[string]any{"domain": domain, "dns_name": "_awid." + domain, "inherited": false, "controller_key": current}
	return &awid.IDChainEvidence{Status: f.status, NamespaceAuthority: authority, AgeSeconds: &age}
}

func (f resignFixture) run(t *testing.T) (map[string]any, *issuanceLog, int, error) {
	t.Helper()
	calls := 0
	signed, err := awid.ResignIDCertificate(f.request, f.parent, f.evidence(0), f.status["domain"].(string), f.log, vectorSigner(t, f.v, f.signer, &calls), f.now)
	return signed, f.log, calls, err
}

func vectorCertificateFields(signed map[string]any) map[string]any {
	c := signed["certificate"].(map[string]any)
	return map[string]any{"id": c["id"], "domain": c["domain"], "parent": c["parent"], "kind": c["kind"]}
}

// The parent's signer holds its current key; the frozen cases are re-signs by alice.
func caseFixture(t *testing.T, v idResignVectors, c idResignCase) resignFixture {
	t.Helper()
	old := v.Certificates[c.Input.OldCertificate].Signed
	requested := vectorCertificateFields(old)
	for k, x := range c.Input.RequestedChange {
		requested[k] = x
	}
	subjectKey := ""
	if c.Input.SubjectKeyProved {
		subjectKey = old["certificate"].(map[string]any)["id"].(string)
	}
	statusName := c.Input.ParentStatus
	if statusName == "" {
		statusName = "normal"
	}
	signer := "alice"
	if statusName == "alice-rotated" {
		signer = "alice_rotated"
	}
	now := time.Date(2026, 10, 26, 0, 30, 0, 0, time.UTC)
	if c.Input.IssuedAt != "" {
		parsed, err := time.Parse(time.RFC3339, c.Input.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		now = parsed
	}
	return resignFixture{
		v:       v,
		request: awid.IDResignRequest{Signed: old, Requested: requested, SubjectKey: subjectKey},
		parent:  v.Keys["alice"].DIDAW,
		status:  v.Statuses[statusName],
		log:     newIssuanceLog(c.Input.IssuedCertificateIDs...),
		signer:  signer,
		now:     now,
	}
}

func TestIDResignFrozenCases(t *testing.T) {
	v := loadIDResignVectors(t)
	want := []string{"resign-after-revoke-refuses", "resign-mismatched-id", "resign-mismatched-kind", "resign-unchanged-child", "resign-forged-old-key-refuses"}
	var cases []idResignCase
	for _, c := range v.Cases {
		if c.Action == "resign" {
			cases = append(cases, c)
		}
	}
	var names []string
	for _, c := range cases {
		names = append(names, c.Name)
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("resign cases=%v want %v", names, want)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			f := caseFixture(t, v, c)
			before := len(f.log.ids)
			signed, log, _, err := f.run(t)
			if !c.Expected.Accepted {
				if got := awid.IDCertificateErrorCode(err); got != c.Expected.Reason {
					t.Fatalf("reason=%q (%v) want %q", got, err, c.Expected.Reason)
				}
				if signed != nil || log.writes != 0 || len(log.ids) != before {
					t.Fatal("a refused re-sign wrote or released a certificate")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(signed, v.Certificates[c.Expected.NewCertificate].Signed) {
				t.Fatalf("got %v want %v", signed, v.Certificates[c.Expected.NewCertificate].Signed)
			}
			if !log.ids[v.Certificates[c.Expected.NewCertificate].CertificateID] || log.writes != 1 {
				t.Fatal("the re-signed certificate was not recorded in the issuance log")
			}
		})
	}
}

func TestIDResignProbes(t *testing.T) {
	v := loadIDResignVectors(t)
	var accepted idResignCase
	for _, c := range v.Cases {
		if c.Name == "resign-unchanged-child" {
			accepted = c
		}
	}
	refuses := func(t *testing.T, f resignFixture, reason string) {
		t.Helper()
		signed, log, _, err := f.run(t)
		if got := awid.IDCertificateErrorCode(err); got != reason {
			t.Fatalf("reason=%q (%v) want %q", got, err, reason)
		}
		if signed != nil || log.writes != 0 {
			t.Fatal("a refused re-sign wrote or released a certificate")
		}
	}
	t.Run("control", func(t *testing.T) {
		if _, _, _, err := caseFixture(t, v, accepted).run(t); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("old machine signing with the retired key", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		f.signer = "alice"
		refuses(t, f, "issuer_key_not_current")
	})
	t.Run("TestZZSecreviewMislabelledSignerRefuses", func(t *testing.T) {
		// A mis-wired signer labels its output with the current key but signs with the retired one.
		f := caseFixture(t, v, accepted)
		seed, err := hex.DecodeString(v.Keys["alice"].SeedHex)
		if err != nil {
			t.Fatal(err)
		}
		retired := ed25519.NewKeyFromSeed(seed)
		label := v.Keys["alice_rotated"].DIDKey
		signed, err := awid.ResignIDCertificate(f.request, f.parent, f.evidence(0), "example.com", f.log, func(payload []byte) (string, []byte, error) {
			return label, ed25519.Sign(retired, payload), nil
		}, f.now)
		if got := awid.IDCertificateErrorCode(err); got != "invalid_signature" {
			t.Fatalf("reason=%q (%v) want invalid_signature", got, err)
		}
		if signed != nil || f.log.writes != 0 {
			t.Fatal("a mislabelled signature was released or recorded")
		}
	})
	t.Run("subject key not proved", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		f.request.SubjectKey = ""
		refuses(t, f, "subject_mismatch")
	})
	t.Run("another key proved", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		f.request.SubjectKey = v.Keys["seat"].DIDKey
		refuses(t, f, "subject_mismatch")
	})
	for field, value := range map[string]any{
		"domain": "other.example",
		"parent": map[string]any{"kind": "identity", "id": v.Keys["bob"].DIDAW},
	} {
		t.Run("substituted "+field, func(t *testing.T) {
			f := caseFixture(t, v, accepted)
			f.request.Requested[field] = value
			refuses(t, f, "resign_binding_mismatch")
		})
	}
	t.Run("certificate addressed to another parent", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		f.parent = v.Keys["bob"].DIDAW
		refuses(t, f, "resign_binding_mismatch")
	})
	t.Run("old signature by a key outside the parent's history", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		old := f.request.Signed["certificate"].(map[string]any)
		forged := map[string]any{}
		for k, x := range old {
			forged[k] = x
		}
		forged["issuer_key"] = v.Keys["bob"].DIDKey
		f.request.Signed = map[string]any{"certificate": forged, "signature": f.request.Signed["signature"]}
		refuses(t, f, "invalid_signature")
	})
	t.Run("requested binding omits a field", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		delete(f.request.Requested, "kind")
		refuses(t, f, "resign_binding_mismatch")
	})
	t.Run("requested binding adds a field", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		f.request.Requested["issuer_key"] = v.Keys["alice_rotated"].DIDKey
		refuses(t, f, "resign_binding_mismatch")
	})
	t.Run("valid old signature by a key outside the parent's history", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		seed, err := hex.DecodeString(v.Keys["bob"].SeedHex)
		if err != nil {
			t.Fatal(err)
		}
		forged := map[string]any{}
		for k, x := range f.request.Signed["certificate"].(map[string]any) {
			forged[k] = x
		}
		forged["issuer_key"] = v.Keys["bob"].DIDKey
		payload, err := awid.IDCertificateSigningBytes(forged)
		if err != nil {
			t.Fatal(err)
		}
		f.request.Signed = map[string]any{"certificate": forged, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), payload))}
		id, err := awid.IDCertificateID(forged)
		if err != nil {
			t.Fatal(err)
		}
		f.log = newIssuanceLog(id)
		refuses(t, f, "invalid_signature")
	})
	t.Run("tampered old signature", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		old := f.request.Signed["certificate"].(map[string]any)
		tampered := map[string]any{}
		for k, x := range old {
			tampered[k] = x
		}
		tampered["issued_at"] = "2026-10-26T00:05:00Z"
		f.request.Signed = map[string]any{"certificate": tampered, "signature": f.request.Signed["signature"]}
		refuses(t, f, "invalid_signature")
	})
	t.Run("issuance log is never seeded from the submission", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		f.log = newIssuanceLog()
		refuses(t, f, "issuance_not_recorded")
		if len(f.log.ids) != 0 {
			t.Fatal("the submitted certificate was recorded")
		}
	})
	t.Run("log holds another certificate of the same child", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		other := map[string]any{}
		for k, x := range f.request.Signed["certificate"].(map[string]any) {
			other[k] = x
		}
		other["issued_at"] = "2026-10-26T00:05:00Z"
		id, err := awid.IDCertificateID(other)
		if err != nil {
			t.Fatal(err)
		}
		f.log = newIssuanceLog(id)
		refuses(t, f, "issuance_not_recorded")
	})
	t.Run("stale parent evidence is unavailable", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		calls := 0
		_, err := awid.ResignIDCertificate(f.request, f.parent, f.evidence(61), "example.com", f.log, vectorSigner(t, v, f.signer, &calls), f.now)
		if got := awid.IDCertificateErrorCode(err); got != "evidence_unavailable" || calls != 0 || f.log.writes != 0 {
			t.Fatalf("reason=%q calls=%d writes=%d", got, calls, f.log.writes)
		}
	})
	t.Run("refusals happen before signing", func(t *testing.T) {
		f := caseFixture(t, v, accepted)
		f.log = newIssuanceLog()
		_, _, calls, _ := f.run(t)
		if calls != 0 {
			t.Fatal("the signer ran for a refused re-sign")
		}
	})
}
