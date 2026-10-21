package appmanifest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type v2VectorFile struct {
	Schema         string                     `json:"schema"`
	ReservedNames  []string                   `json:"reserved_names"`
	BaseManifests  map[string]json.RawMessage `json:"base_manifests"`
	Cases          []v2LoadCase               `json:"cases"`
	RawCases       []v2RawCase                `json:"raw_cases"`
	CallCases      []v2CallCase               `json:"call_cases"`
	AnswerPayloads []v2AnswerCase             `json:"answer_payload_cases"`
}

type v2Mutation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type v2Expected struct {
	Accepted bool            `json:"accepted"`
	Error    string          `json:"error"`
	Resolved json.RawMessage `json:"resolved"`
}

type v2LoadCase struct {
	Name      string       `json:"name"`
	Base      string       `json:"base"`
	Mutations []v2Mutation `json:"mutations"`
	Expected  v2Expected   `json:"expected"`
}

type v2RawCase struct {
	Name     string     `json:"name"`
	Bytes    string     `json:"bytes"`
	Expected v2Expected `json:"expected"`
}

type v2CallCase struct {
	Name        string          `json:"name"`
	Base        string          `json:"base"`
	Mutations   []v2Mutation    `json:"mutations"`
	Tool        string          `json:"tool"`
	Attestation json.RawMessage `json:"attestation"`
	Expected    string          `json:"expected"`
}

type v2AnswerCase struct {
	Name     string          `json:"name"`
	Base     string          `json:"base"`
	Tool     string          `json:"tool"`
	Body     json.RawMessage `json:"body"`
	Expected string          `json:"expected"`
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

func readAppManifestVectors(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRootForTest(t), "test-vectors", "app-manifests", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func loadV2Vectors(t *testing.T) (v2VectorFile, map[string]bool) {
	t.Helper()
	var vectors v2VectorFile
	readAppManifestVectors(t, "app-manifest-v2-v1.json", &vectors)
	if vectors.Schema != "aweb.app-manifest.v2.v1" {
		t.Fatalf("schema=%q", vectors.Schema)
	}
	reserved := map[string]bool{}
	for _, name := range vectors.ReservedNames {
		reserved[name] = true
	}
	return vectors, reserved
}

// mutatedManifest applies the vector's JSON Pointer mutations to a copy of
// the base manifest and returns its JSON bytes.
func mutatedManifest(t *testing.T, base json.RawMessage, mutations []v2Mutation) []byte {
	t.Helper()
	var doc any
	dec := json.NewDecoder(bytes.NewReader(base))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	for _, m := range mutations {
		var value any
		if m.Op == "set" {
			vdec := json.NewDecoder(bytes.NewReader(m.Value))
			vdec.UseNumber()
			if err := vdec.Decode(&value); err != nil {
				t.Fatalf("mutation value %s: %v", m.Path, err)
			}
		}
		doc = applyPointer(t, doc, strings.Split(m.Path, "/")[1:], m.Op, value)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func applyPointer(t *testing.T, node any, tokens []string, op string, value any) any {
	t.Helper()
	token := strings.ReplaceAll(strings.ReplaceAll(tokens[0], "~1", "/"), "~0", "~")
	last := len(tokens) == 1
	switch n := node.(type) {
	case map[string]any:
		if last {
			if op == "remove" {
				if _, ok := n[token]; !ok {
					t.Fatalf("remove missing member %q", token)
				}
				delete(n, token)
			} else {
				n[token] = value
			}
			return n
		}
		n[token] = applyPointer(t, n[token], tokens[1:], op, value)
		return n
	case []any:
		if token == "-" {
			if !last || op != "set" {
				t.Fatalf("'-' only appends")
			}
			return append(n, value)
		}
		i, err := strconv.Atoi(token)
		if err != nil || i < 0 || i >= len(n) {
			t.Fatalf("bad array index %q", token)
		}
		if last {
			if op == "remove" {
				return append(n[:i], n[i+1:]...)
			}
			n[i] = value
			return n
		}
		n[i] = applyPointer(t, n[i], tokens[1:], op, value)
		return n
	default:
		t.Fatalf("pointer token %q into non-container", token)
		return nil
	}
}

func assertLoadOutcome(t *testing.T, data []byte, reserved map[string]bool, expected v2Expected) {
	t.Helper()
	resolved, err := Load(data, reserved)
	if !expected.Accepted {
		if err == nil {
			t.Fatalf("accepted; want error %s", expected.Error)
		}
		if got := ErrorCode(err); got != expected.Error {
			t.Fatalf("error code %q want %q (%v)", got, expected.Error, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("refused (%s): %v", ErrorCode(err), err)
	}
	got, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expected.Resolved, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("resolved mismatch\n got: %s\nwant: %s", got, expected.Resolved)
	}
}

func TestManifestV2LoadVectors(t *testing.T) {
	vectors, reserved := loadV2Vectors(t)
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			assertLoadOutcome(t, mutatedManifest(t, vectors.BaseManifests[tc.Base], tc.Mutations), reserved, tc.Expected)
		})
	}
	for _, tc := range vectors.RawCases {
		t.Run("raw/"+tc.Name, func(t *testing.T) {
			assertLoadOutcome(t, []byte(tc.Bytes), reserved, tc.Expected)
		})
	}
}

func TestManifestV2CallContextVectors(t *testing.T) {
	vectors, reserved := loadV2Vectors(t)
	for _, tc := range vectors.CallCases {
		t.Run(tc.Name, func(t *testing.T) {
			resolved, err := Load(mutatedManifest(t, vectors.BaseManifests[tc.Base], tc.Mutations), reserved)
			if err != nil {
				t.Fatal(err)
			}
			var attestation *Attestation
			if len(tc.Attestation) > 0 && string(tc.Attestation) != "null" {
				attestation = &Attestation{}
				if err := json.Unmarshal(tc.Attestation, attestation); err != nil {
					t.Fatal(err)
				}
			}
			got := "context_allowed"
			if err := resolved.CheckInvocationContext(tc.Tool, attestation); err != nil {
				got = ErrorCode(err)
			}
			if got != tc.Expected {
				t.Fatalf("got %q want %q", got, tc.Expected)
			}
		})
	}
}

func TestManifestV2AnswerPayloadVectors(t *testing.T) {
	vectors, reserved := loadV2Vectors(t)
	for _, tc := range vectors.AnswerPayloads {
		t.Run(tc.Name, func(t *testing.T) {
			resolved, err := Load(mutatedManifest(t, vectors.BaseManifests[tc.Base], nil), reserved)
			if err != nil {
				t.Fatal(err)
			}
			var body any
			if err := json.Unmarshal(tc.Body, &body); err != nil {
				t.Fatal(err)
			}
			got := "not_refused"
			if err := resolved.CheckAnswerPayload(tc.Tool, body); err != nil {
				got = ErrorCode(err)
			}
			if got != tc.Expected {
				t.Fatalf("got %q want %q", got, tc.Expected)
			}
		})
	}
}

type discoveryResponse struct {
	Status   int    `json:"status"`
	Body     string `json:"body"`
	Location string `json:"location"`
}

func TestManifestDiscoveryVectors(t *testing.T) {
	var vectors struct {
		Schema string `json:"schema"`
		Cases  []struct {
			Name      string                       `json:"name"`
			Origin    string                       `json:"origin"`
			Supported []int                        `json:"supported_versions"`
			Responses map[string]discoveryResponse `json:"responses"`
			Expected  struct {
				Error           string `json:"error"`
				Source          string `json:"source"`
				ManifestVersion int    `json:"manifest_version"`
				URL             string `json:"url"`
				Digest          string `json:"digest"`
			} `json:"expected"`
		} `json:"cases"`
	}
	readAppManifestVectors(t, "app-manifest-discovery-v1.json", &vectors)
	if vectors.Schema != "aweb.app-manifest.discovery.v1" {
		t.Fatalf("schema=%q", vectors.Schema)
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var fetched []string
			fetch := func(path string, maxBytes int64) (int, []byte, error) {
				fetched = append(fetched, path)
				r, ok := tc.Responses[path]
				if !ok {
					return 404, nil, nil
				}
				return r.Status, []byte(r.Body), nil
			}
			got, err := SelectVariant(tc.Origin, tc.Supported, fetch)
			if tc.Expected.Error != "" {
				if err == nil {
					t.Fatalf("selected %+v; want %s", got, tc.Expected.Error)
				}
				if code := ErrorCode(err); code != tc.Expected.Error {
					t.Fatalf("error code %q want %q (%v)", code, tc.Expected.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused (%s): %v", ErrorCode(err), err)
			}
			if got.Source != tc.Expected.Source || got.ManifestVersion != tc.Expected.ManifestVersion || got.URL != tc.Expected.URL || got.Digest != tc.Expected.Digest {
				t.Fatalf("selected %+v want %+v", got, tc.Expected)
			}
			if string(got.Bytes) != tc.Responses[strings.TrimPrefix(got.URL, tc.Origin)].Body {
				t.Fatalf("selected bytes are not the served bytes")
			}
			for _, path := range fetched {
				if path != DiscoveryCatalogPath && path != LegacyManifestPath && path != strings.TrimPrefix(got.URL, tc.Origin) {
					t.Fatalf("fetched unexpected path %s", path)
				}
			}
		})
	}
}
