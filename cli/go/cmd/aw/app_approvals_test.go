package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppApprovalMintSelection(t *testing.T) {
	f := setupAppCustodyFixture(t, nil)
	dir, _ := pluginDir()
	original, err := os.ReadFile(manifestPluginManifestPath(dir, "testapp"))
	if err != nil {
		t.Fatal(err)
	}
	other := strings.ReplaceAll(string(original), `"id":"testapp"`, `"id":"otherapp"`)
	otherPath := manifestPluginManifestPath(dir, "otherapp")
	if err := os.MkdirAll(filepath.Dir(otherPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, []byte(other), 0600); err != nil {
		t.Fatal(err)
	}
	// Shared installations do not silently become authority on upgrade.
	empty, err := selectGrantAppSnapshots(f.residentHome, false, nil, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty catalog: apps=%d err=%v", len(empty), err)
	}
	if err := changeAppApproval(f.residentHome, "otherapp", f.app.server.URL); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(appApprovalsPath(f.residentHome))
	selected, err := selectGrantAppSnapshots(f.residentHome, true, []string{"testapp:get-thing"}, nil)
	if err != nil || len(selected) != 1 || len(selected["testapp"].Tools) != 1 {
		t.Fatalf("explicit selection: %v", err)
	}
	if _, ok := selected["otherapp"]; ok {
		t.Fatal("explicit selection unioned catalog")
	}
	after, _ := os.ReadFile(appApprovalsPath(f.residentHome))
	if !bytes.Equal(before, after) {
		t.Fatal("explicit selection changed approvals")
	}
	for _, values := range [][]string{nil, {""}, {"testapp:"}, {"missing:get"}, {"testapp:nope"}, {"testapp:get-thing,"}} {
		if _, err := selectGrantAppSnapshots(f.residentHome, true, values, nil); err == nil {
			t.Fatalf("invalid explicit selection fell back: %v", values)
		}
	}
	all, err := selectGrantAppSnapshots(f.residentHome, false, nil, nil)
	if err != nil || len(all) != 1 || len(all["otherapp"].Tools) != 3 {
		t.Fatalf("approved signed tools: %v %+v", err, all)
	}
	assertSkip := func(code string, denied []string) {
		t.Helper()
		apps, skipped, err := prepareGrantAppSnapshots(f.residentHome, false, nil, denied)
		if err != nil || len(apps) != 0 || len(skipped) != 1 || skipped[0].Code != code {
			t.Fatalf("skip %s: apps=%d skipped=%v err=%v", code, len(apps), skipped, err)
		}
	}
	assertSkip("app_origin_denied", []string{f.app.server.URL})
	if err := changeAppApproval(f.residentHome, "otherapp", "https://different.invalid"); err != nil {
		t.Fatal(err)
	}
	assertSkip("app_origin_mismatch", nil)

	// Approval is checked against the same bytes captured in the snapshot.
	if err := changeAppApproval(f.residentHome, "otherapp", f.app.server.URL); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	assertSkip("app_manifest_mismatch", nil)

	if err := os.WriteFile(otherPath, []byte(other), 0600); err != nil {
		t.Fatal(err)
	}
	all, err = selectGrantAppSnapshots(f.residentHome, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveGrantAppToolsSnapshot(f.residentHome, &grantAppToolsSnapshot{Version: 1, GrantID: appTestGrantID, TeamID: f.grant.TeamID, Apps: all}); err != nil {
		t.Fatal(err)
	}
	snapshotBefore, _ := loadGrantAppToolsSnapshot(f.residentHome, appTestGrantID)
	if err := changeAppApproval(f.residentHome, "otherapp", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, []byte(strings.ReplaceAll(other, "/v1/things", "/v1/redirected")), 0600); err != nil {
		t.Fatal(err)
	}
	snapshotAfter, _ := loadGrantAppToolsSnapshot(f.residentHome, appTestGrantID)
	a, _ := json.Marshal(snapshotBefore)
	b, _ := json.Marshal(snapshotAfter)
	if !bytes.Equal(a, b) {
		t.Fatal("existing snapshot changed after remove/store drift")
	}
	inventory := grantAppInventory(all)
	if len(inventory) != 1 || inventory[0].AppID != "otherapp" || len(inventory[0].Tools) != 3 || inventory[0].ManifestSHA256 == "" {
		t.Fatalf("actual inventory: %+v", inventory)
	}
}

func TestAppApprovalCatalogRejectsMalformedAndSymlinks(t *testing.T) {
	home := t.TempDir()
	for _, raw := range []string{`null`, `{}`, `{"version":1,"apps":null}`, `{"version":2,"apps":{}}`, `{"version":1,"apps":{},"unknown":1}`, `{"version":1,"apps":{"../bad":"https://example.com"}}`, `{"version":1,"apps":{"testapp":"https://example.com/path"}}`} {
		if err := os.WriteFile(appApprovalsPath(home), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAppApprovals(home); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if err := os.Remove(appApprovalsPath(home)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "catalog")
	if err := os.WriteFile(target, []byte(`{"version":1,"apps":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, appApprovalsPath(home)); err != nil {
		t.Fatal(err)
	}
	if err := changeAppApproval(home, "testapp", "https://example.com"); err == nil {
		t.Fatal("followed catalog symlink")
	}
}
