package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	awid "github.com/awebai/aw/awid"
)

type idChildRequestVectors struct {
	Certificates map[string]struct {
		Signed map[string]any `json:"signed"`
	} `json:"certificates"`
	ChildRequests struct {
		PrefixUTF8   string `json:"prefix_utf8"`
		MaxFileBytes int    `json:"max_file_bytes"`
		Requests     map[string]struct {
			Signed          map[string]any `json:"signed"`
			CanonicalUTF8   string         `json:"canonical_utf8"`
			SigningBytesHex string         `json:"signing_bytes_hex"`
			KeyFingerprint  string         `json:"key_fingerprint"`
			Expected        struct {
				Accepted bool    `json:"accepted"`
				Reason   *string `json:"reason"`
			} `json:"expected"`
		} `json:"requests"`
		FileRefusals []struct {
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			UnitUTF8  string `json:"unit_utf8"`
			Repeat    int    `json:"repeat"`
			FileBytes int    `json:"file_bytes"`
			Expected  struct {
				Reason string `json:"reason"`
			} `json:"expected"`
		} `json:"file_refusals"`
		Responses map[string]struct {
			Response        map[string]any `json:"response"`
			CanonicalUTF8   string         `json:"canonical_utf8"`
			Request         string         `json:"request"`
			LeafCertificate string         `json:"leaf_certificate"`
		} `json:"responses"`
	} `json:"child_requests"`
}

func loadIDChildRequestVectors(t *testing.T) idChildRequestVectors {
	t.Helper()
	var v idChildRequestVectors
	d := json.NewDecoder(bytes.NewReader(readRootVector(t, "id-certificates-v1.json")))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestIDChildRequestFrozenRequests(t *testing.T) {
	v := loadIDChildRequestVectors(t)
	if v.ChildRequests.PrefixUTF8 != awid.IDCertificateRequestPrefix || v.ChildRequests.MaxFileBytes != awid.IDCertificateRequestMaxBytes {
		t.Fatal("request prefix or file cap differs from the frozen vectors")
	}
	var names []string
	for name := range v.ChildRequests.Requests {
		names = append(names, name)
	}
	sort.Strings(names)
	want := []string{"bad-subject-signature", "human-issue", "human-second-key", "human-second-request-same-key", "local-resign", "local-resign-substituted-parent", "local-resign-unrecorded"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("requests=%v want %v", names, want)
	}
	for _, name := range names {
		c := v.ChildRequests.Requests[name]
		t.Run(name, func(t *testing.T) {
			request := c.Signed["request"].(map[string]any)
			signing, err := awid.IDCertificateRequestSigningBytes(request)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(signing) != c.SigningBytesHex {
				t.Fatal("signing bytes differ from the frozen vector")
			}
			fingerprint, err := awid.IDKeyFingerprint(request["subject_key"].(string))
			if err != nil || fingerprint != c.KeyFingerprint {
				t.Fatalf("fingerprint=%q (%v) want %q", fingerprint, err, c.KeyFingerprint)
			}
			parsed, err := awid.ParseIDCertificateRequest([]byte(c.CanonicalUTF8))
			if !c.Expected.Accepted {
				if got := awid.IDCertificateErrorCode(err); got != *c.Expected.Reason || parsed != nil {
					t.Fatalf("reason=%q (%v) want %q", got, err, *c.Expected.Reason)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(parsed, c.Signed) {
				t.Fatalf("parsed %v want %v", parsed, c.Signed)
			}
		})
	}
}

func TestIDChildRequestFrozenResponses(t *testing.T) {
	v := loadIDChildRequestVectors(t)
	if len(v.ChildRequests.Responses) != 2 {
		t.Fatalf("responses=%d want 2", len(v.ChildRequests.Responses))
	}
	for name, c := range v.ChildRequests.Responses {
		t.Run(name, func(t *testing.T) {
			parsed, err := awid.ParseIDCertificateResponse([]byte(c.CanonicalUTF8))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(parsed, c.Response) {
				t.Fatalf("parsed %v want %v", parsed, c.Response)
			}
			request := v.ChildRequests.Requests[c.Request].Signed["request"].(map[string]any)
			if parsed["request_id"] != request["request_id"] {
				t.Fatal("response does not correlate with its request")
			}
			certs := parsed["chain"].(map[string]any)["certificates"].([]any)
			if !reflect.DeepEqual(certs[len(certs)-1], v.Certificates[c.LeafCertificate].Signed) {
				t.Fatal("response leaf is not the frozen certificate")
			}
			built, err := awid.EncodeIDCertificateResponse(request["request_id"].(string), parsed["chain"].(map[string]any))
			if err != nil || string(built) != c.CanonicalUTF8 {
				t.Fatalf("encoded response differs (%v)", err)
			}
		})
	}
}

func TestIDChildRequestRefusals(t *testing.T) {
	v := loadIDChildRequestVectors(t)
	base := v.ChildRequests.Requests["human-issue"]
	resign := v.ChildRequests.Requests["local-resign"]
	refuses := func(t *testing.T, raw []byte, reason string) {
		t.Helper()
		parsed, err := awid.ParseIDCertificateRequest(raw)
		if got := awid.IDCertificateErrorCode(err); got != reason || parsed != nil {
			t.Fatalf("reason=%q (%v) want %q", got, err, reason)
		}
	}
	// mutate re-encodes a frozen request with one field changed; the signature no
	// longer covers it, so shape refusals must come before the key proof.
	mutate := func(t *testing.T, signed map[string]any, field string, value any) []byte {
		t.Helper()
		request := map[string]any{}
		for k, x := range signed["request"].(map[string]any) {
			request[k] = x
		}
		request[field] = value
		raw, err := awid.CanonicalJSONValue(map[string]any{"request": request, "signature": signed["signature"]})
		if err != nil {
			t.Fatal(err)
		}
		return []byte(raw)
	}
	withoutField := func(t *testing.T, signed map[string]any, field string) []byte {
		t.Helper()
		request := map[string]any{}
		for k, x := range signed["request"].(map[string]any) {
			if k != field {
				request[k] = x
			}
		}
		raw, err := awid.CanonicalJSONValue(map[string]any{"request": request, "signature": signed["signature"]})
		if err != nil {
			t.Fatal(err)
		}
		return []byte(raw)
	}

	t.Run("noncanonical whitespace", func(t *testing.T) {
		refuses(t, []byte(strings.Replace(base.CanonicalUTF8, ",", ", ", 1)), "noncanonical_json")
	})
	t.Run("duplicate key", func(t *testing.T) {
		refuses(t, []byte(strings.Replace(base.CanonicalUTF8, `{"request":{`, `{"request":{"v":1,`, 1)), "invalid_json")
	})
	t.Run("trailing value", func(t *testing.T) {
		refuses(t, []byte(base.CanonicalUTF8+"{}"), "invalid_json")
	})
	t.Run("unknown wrapper field", func(t *testing.T) {
		raw, err := awid.CanonicalJSONValue(map[string]any{"request": base.Signed["request"], "signature": base.Signed["signature"], "email": "a@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		refuses(t, []byte(raw), "invalid_shape")
	})
	t.Run("subject key outside the prime subgroup", func(t *testing.T) {
		smallOrder := make([]byte, 32)
		smallOrder[0] = 1
		refuses(t, mutate(t, base.Signed, "subject_key", awid.ComputeDIDKey(smallOrder)), "invalid_shape")
	})
	t.Run("unknown request field", func(t *testing.T) {
		refuses(t, mutate(t, base.Signed, "email", "a@example.com"), "invalid_shape")
	})
	t.Run("missing request field", func(t *testing.T) {
		refuses(t, withoutField(t, base.Signed, "old_certificate"), "invalid_shape")
	})
	t.Run("wrong type", func(t *testing.T) {
		refuses(t, mutate(t, base.Signed, "type", "aweb.id-certificate"), "invalid_shape")
	})
	t.Run("uppercase request id", func(t *testing.T) {
		refuses(t, mutate(t, base.Signed, "request_id", "20000000-0000-4000-8000-00000000000A"), "invalid_shape")
	})
	t.Run("unknown operation", func(t *testing.T) {
		refuses(t, mutate(t, base.Signed, "operation", "adopt"), "invalid_shape")
	})
	t.Run("issue without invitation id", func(t *testing.T) {
		refuses(t, mutate(t, base.Signed, "invitation_id", nil), "invalid_shape")
	})
	t.Run("issue with an old certificate", func(t *testing.T) {
		refuses(t, mutate(t, base.Signed, "old_certificate", v.Certificates["coordinator"].Signed), "invalid_shape")
	})
	t.Run("resign with an invitation id", func(t *testing.T) {
		refuses(t, mutate(t, resign.Signed, "invitation_id", "10000000-0000-4000-8000-000000000001"), "invalid_shape")
	})
	t.Run("resign without an old certificate", func(t *testing.T) {
		refuses(t, mutate(t, resign.Signed, "old_certificate", nil), "invalid_shape")
	})
	t.Run("resign of a human", func(t *testing.T) {
		refuses(t, mutate(t, resign.Signed, "kind", "human"), "invalid_shape")
	})
	t.Run("did:key child whose subject key is another key", func(t *testing.T) {
		refuses(t, mutate(t, resign.Signed, "subject_key", base.Signed["request"].(map[string]any)["subject_key"]), "invalid_shape")
	})
	t.Run("human did:key id", func(t *testing.T) {
		refuses(t, mutate(t, base.Signed, "id", base.Signed["request"].(map[string]any)["subject_key"]), "invalid_shape")
	})
	t.Run("padded signature", func(t *testing.T) {
		refuses(t, []byte(strings.Replace(base.CanonicalUTF8, base.Signed["signature"].(string), base.Signed["signature"].(string)+"==", 1)), "invalid_encoding")
	})
	t.Run("signature over another request", func(t *testing.T) {
		refuses(t, mutate(t, base.Signed, "request_id", "20000000-0000-4000-8000-000000000099"), "invalid_signature")
	})
}

func TestIDChildResponseRefusals(t *testing.T) {
	v := loadIDChildRequestVectors(t)
	base := v.ChildRequests.Responses["local-resigned"]
	refuses := func(t *testing.T, raw string, reason string) {
		t.Helper()
		parsed, err := awid.ParseIDCertificateResponse([]byte(raw))
		if got := awid.IDCertificateErrorCode(err); got != reason || parsed != nil {
			t.Fatalf("reason=%q (%v) want %q", got, err, reason)
		}
	}
	t.Run("noncanonical", func(t *testing.T) {
		refuses(t, strings.Replace(base.CanonicalUTF8, ",", ", ", 1), "noncanonical_json")
	})
	t.Run("unknown field", func(t *testing.T) {
		refuses(t, strings.Replace(base.CanonicalUTF8, `{"chain":`, `{"callback":"x","chain":`, 1), "invalid_shape")
	})
	t.Run("tampered chain signature", func(t *testing.T) {
		refuses(t, strings.Replace(base.CanonicalUTF8, `"issued_at":"2026-10-26T00:11:00Z"`, `"issued_at":"2026-10-26T00:12:00Z"`, 1), "invalid_signature")
	})
}

func TestIDChildFileRefusals(t *testing.T) {
	v := loadIDChildRequestVectors(t)
	var names []string
	for _, c := range v.ChildRequests.FileRefusals {
		names = append(names, c.Name)
	}
	want := []string{"csr-request-file-over-limit", "csr-request-file-at-limit-invalid-json", "csr-response-file-over-limit", "csr-response-file-at-limit-invalid-json"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("file refusals=%v want %v", names, want)
	}
	for _, c := range v.ChildRequests.FileRefusals {
		t.Run(c.Name, func(t *testing.T) {
			raw := bytes.Repeat([]byte(c.UnitUTF8), c.Repeat)
			if len(raw) != c.FileBytes {
				t.Fatalf("recipe builds %d bytes want %d", len(raw), c.FileBytes)
			}
			var parsed map[string]any
			var err error
			switch c.Kind {
			case "request":
				parsed, err = awid.ParseIDCertificateRequest(raw)
			case "response":
				parsed, err = awid.ParseIDCertificateResponse(raw)
			default:
				t.Fatalf("unknown recipe kind %q", c.Kind)
			}
			if got := awid.IDCertificateErrorCode(err); got != c.Expected.Reason || parsed != nil {
				t.Fatalf("reason=%q (%v) want %q", got, err, c.Expected.Reason)
			}
		})
	}
}
