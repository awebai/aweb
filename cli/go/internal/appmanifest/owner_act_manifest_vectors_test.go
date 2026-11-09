package appmanifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type ownerActManifestCase struct {
	Name      string          `json:"name"`
	AppOrigin string          `json:"app_origin"`
	OwnerActs json.RawMessage `json:"owner_acts"`
	Error     *string         `json:"error"`
}

func ownerActManifestCases(t *testing.T) []ownerActManifestCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRootForTest(t), "docs", "vectors", "owner-act-delivery-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		ManifestCases []ownerActManifestCase `json:"manifest_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.ManifestCases) == 0 {
		t.Fatal("no manifest_cases")
	}
	return vectors.ManifestCases
}

// ownerActCaseManifest is the version 3 manifest a case's owner_acts belongs to.
func ownerActCaseManifest(t *testing.T, appOrigin string, ownerActs json.RawMessage) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"manifest_version": 3,
		"app":              map[string]any{"id": "example", "version": "1.0.0", "origin": appOrigin},
		"tools":            []any{},
		"owner_acts":       ownerActs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOwnerActManifestVectors(t *testing.T) {
	for _, tc := range ownerActManifestCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			resolved, err := Load(ownerActCaseManifest(t, tc.AppOrigin, tc.OwnerActs), nil)
			if tc.Error != nil {
				if code := ErrorCode(err); code != *tc.Error {
					t.Fatalf("code %q want %q (%v)", code, *tc.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused (%s): %v", ErrorCode(err), err)
			}
			got, err := json.Marshal(resolved.OwnerActs)
			if err != nil {
				t.Fatal(err)
			}
			var gotValue, wantValue any
			if err := json.Unmarshal(got, &gotValue); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(tc.OwnerActs, &wantValue); err != nil {
				t.Fatal(err)
			}
			// A null member reads as absent, so the resolved form omits it.
			if !reflect.DeepEqual(gotValue, withoutNullMembers(wantValue)) {
				t.Fatalf("owner_acts\n got: %s\nwant: %s", got, tc.OwnerActs)
			}
		})
	}
}

// Version 3 is version 2 plus owner_acts, so every version 2 load verdict
// holds unchanged under version 3.
func TestManifestV3KeepsEveryVersion2LoadVerdict(t *testing.T) {
	vectors, reserved := loadV2Vectors(t)
	for _, tc := range vectors.Cases {
		if tc.Base != "v2" || touchesManifestVersion(tc.Mutations) {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(mutatedManifest(t, vectors.BaseManifests[tc.Base], tc.Mutations), &doc); err != nil {
				t.Fatal(err)
			}
			doc["manifest_version"] = 3
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			expected := tc.Expected
			if expected.Accepted {
				var resolved map[string]any
				if err := json.Unmarshal(expected.Resolved, &resolved); err != nil {
					t.Fatal(err)
				}
				resolved["manifest_version"] = 3
				if expected.Resolved, err = json.Marshal(resolved); err != nil {
					t.Fatal(err)
				}
			}
			assertLoadOutcome(t, data, reserved, expected)
		})
	}
}

func touchesManifestVersion(mutations []v2Mutation) bool {
	for _, m := range mutations {
		if strings.HasPrefix(m.Path, "/manifest_version") {
			return true
		}
	}
	return false
}

func TestOwnerActsOriginIsSeparatedFromAPaddedAppOrigin(t *testing.T) {
	cases := ownerActManifestCases(t)
	var ownerActs struct {
		Origin string `json:"origin"`
	}
	if err := json.Unmarshal(cases[0].OwnerActs, &ownerActs); err != nil {
		t.Fatal(err)
	}
	_, err := Load(ownerActCaseManifest(t, " "+ownerActs.Origin+" ", cases[0].OwnerActs), nil)
	if code := ErrorCode(err); code != CodeOwnerActsInvalid {
		t.Fatalf("code %q, err %v", code, err)
	}
}

// asVersion3 is a version 2 vector manifest relabelled as version 3.
func asVersion3(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["manifest_version"] = 3
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestManifestV3KeepsEveryVersion2AnswerPayloadVerdict(t *testing.T) {
	vectors, reserved := loadV2Vectors(t)
	for _, tc := range vectors.AnswerPayloads {
		if strings.HasSuffix(tc.Base, "v1") {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			resolved, err := Load(asVersion3(t, mutatedManifest(t, vectors.BaseManifests[tc.Base], nil)), reserved)
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

func TestManifestV3KeepsEveryVersion2CallContextVerdict(t *testing.T) {
	vectors, reserved := loadV2Vectors(t)
	for _, tc := range vectors.CallCases {
		if strings.HasSuffix(tc.Base, "v1") {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			resolved, err := Load(asVersion3(t, mutatedManifest(t, vectors.BaseManifests[tc.Base], tc.Mutations)), reserved)
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

// withoutNullMembers drops every object member whose value is null, at any
// depth.
func withoutNullMembers(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for name, member := range v {
			if member != nil {
				out[name] = withoutNullMembers(member)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = withoutNullMembers(item)
		}
		return out
	default:
		return value
	}
}
