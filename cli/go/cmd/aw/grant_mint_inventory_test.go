package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/awebai/aw/internal/appmanifest"
)

// These public, secret-free receipts are consumed by launch integrations.
// Compare the entire serialized output, including the nested tools string array.
func TestGrantMintInventoryFixtures(t *testing.T) {
	app := func(id string, verbs ...string) grantAppSnapshot {
		tools := []appmanifest.Tool{}
		for _, verb := range verbs {
			tools = append(tools, appmanifest.Tool{Name: verb})
		}
		return grantAppSnapshot{App: appmanifest.App{ID: id, Origin: "https://" + id + ".example"}, ManifestSHA256: "sha256:" + strings.Repeat("0", 64), Tools: tools}
	}
	for _, tc := range []struct {
		name    string
		apps    map[string]grantAppSnapshot
		skipped []skippedGrantApp
	}{
		{"empty", nil, []skippedGrantApp{}},
		{"catalog", map[string]grantAppSnapshot{"shelf": app("shelf", "read"), "notes": app("notes", "list", "create")}, []skippedGrantApp{}},
		{"legacy", map[string]grantAppSnapshot{"notes": app("notes", "list")}, []skippedGrantApp{}},
		{"skipped", map[string]grantAppSnapshot{"shelf": app("shelf", "read")}, []skippedGrantApp{{AppID: "notes", Code: "app_origin_mismatch"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := grantMintOutput{GrantID: "00000000-0000-4000-8000-000000000001", ExpiresAt: "2030-01-01T01:00:00Z", TeamID: "demo:example.com", Alias: "worker", Out: "/tmp/synthetic-grant", CustodySocketPath: "/tmp/synthetic-custody.sock", Apps: grantAppInventory(tc.apps), SkippedApps: tc.skipped}
			generated, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			fixture, err := os.ReadFile("testdata/grant-mint/" + tc.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(generated, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(fixture, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("mint inventory fixture %s differs from serializer", tc.name)
			}
		})
	}
}
