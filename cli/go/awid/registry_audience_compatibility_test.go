package awid

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// preOwnerRegistryOrigin is the removed private function from
// 39d50de012:registry_register.go:48-59, retained only as a compatibility oracle.
func preOwnerRegistryOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if strings.TrimRight(parsed.Path, "/") == "/api" {
		parsed.Path = ""
		parsed.RawPath = ""
	}
	return canonicalServerOrigin(parsed.String())
}

func TestRegistryOwnerPreservesFrozenControllerAudienceBytes(t *testing.T) {
	var writes struct {
		Origin string `json:"registry_origin"`
		Cases  []struct {
			Name     string `json:"name"`
			Expected struct {
				Method  string            `json:"method"`
				Path    string            `json:"raw_path"`
				Body    string            `json:"body_utf8"`
				Headers map[string]string `json:"headers"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readDocsVector(t, "awid-controller-writes-v1.json"), &writes); err != nil {
		t.Fatal(err)
	}
	for _, tc := range writes.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			frozen, err := base64.RawURLEncoding.DecodeString(tc.Expected.Headers["x-aweb-signed-payload"])
			if err != nil {
				t.Fatal(err)
			}
			var fields struct{ Aud, Timestamp, Domain, Operation string }
			if err := json.Unmarshal(frozen, &fields); err != nil {
				t.Fatal(err)
			}
			claims := make(map[string]any)
			decoder := json.NewDecoder(bytes.NewReader(frozen))
			decoder.UseNumber()
			if err := decoder.Decode(&claims); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"v", "type", "aud", "method", "path", "body_sha256", "timestamp", "domain", "operation"} {
				delete(claims, name)
			}
			for _, suffix := range []string{"", "/", "/api", "/api/"} {
				input := writes.Origin + suffix
				before, err := preOwnerRegistryOrigin(input)
				if err != nil {
					t.Fatal(err)
				}
				after, err := CanonicalRegistryServerOrigin(input)
				if err != nil {
					t.Fatal(err)
				}
				if before != after || after != fields.Aud {
					t.Fatalf("%s changed audience bytes: before=%q after=%q frozen=%q", input, before, after, fields.Aud)
				}
				oldPayload, err := ControllerRequestPayload(before, tc.Expected.Method, tc.Expected.Path, []byte(tc.Expected.Body), fields.Timestamp, fields.Domain, fields.Operation, claims)
				if err != nil {
					t.Fatal(err)
				}
				newPayload, err := ControllerRequestPayload(after, tc.Expected.Method, tc.Expected.Path, []byte(tc.Expected.Body), fields.Timestamp, fields.Domain, fields.Operation, claims)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(oldPayload, newPayload) || !bytes.Equal(newPayload, frozen) {
					t.Fatalf("%s changed frozen signed payload for %s", input, tc.Name)
				}
			}
		})
	}
	if len(writes.Cases) == 0 {
		t.Fatal("frozen controller write cases missing")
	}
	var atomic atomicAddressClaimVector
	if err := json.Unmarshal(readDocsVector(t, "atomic-address-claim-v1.json"), &atomic); err != nil {
		t.Fatal(err)
	}
	for _, alias := range atomic.RegistryURLAliases {
		before, err := preOwnerRegistryOrigin(alias.Input)
		if err != nil {
			t.Fatal(err)
		}
		after, err := CanonicalRegistryServerOrigin(alias.Input)
		if err != nil {
			t.Fatal(err)
		}
		if before != after || after != alias.Canonical {
			t.Fatalf("frozen atomic alias changed: before=%q after=%q frozen=%q", before, after, alias.Canonical)
		}
	}
}

func TestRegistryOwnerDoesNotCollapseDistinctLoopbackAudiences(t *testing.T) {
	inputs := []string{"http://localhost:8010", "http://127.0.0.1:8010"}
	var previous string
	for _, input := range inputs {
		before, err := preOwnerRegistryOrigin(input)
		if err != nil {
			t.Fatal(err)
		}
		after, err := CanonicalRegistryServerOrigin(input + "/api/")
		if err != nil {
			t.Fatal(err)
		}
		if before != after || after == previous {
			t.Fatalf("loopback audience changed: before=%q after=%q previous=%q", before, after, previous)
		}
		previous = after
	}
}
