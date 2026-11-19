package chat

import (
	"bytes"
	"encoding/json"
	"github.com/awebai/aw/awid"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeliveryReceiptMarkerReadFailureDoesNotSelectAnotherStore(t *testing.T) {
	operations := []struct {
		name string
		run  func(string) ([]awid.ChatMessage, error)
	}{
		{name: "read", run: func(workspace string) ([]awid.ChatMessage, error) {
			_, err := LoadDeliveredIDsForDir(workspace)
			return nil, err
		}},
		{name: "write", run: func(workspace string) ([]awid.ChatMessage, error) {
			return nil, SaveDeliveredIDsForDir(workspace, []string{"accepted-message"})
		}},
		{name: "filter", run: func(workspace string) ([]awid.ChatMessage, error) {
			return FilterDeliveredMessagesForDir(workspace, []awid.ChatMessage{{MessageID: "accepted-message"}})
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			t.Setenv(DeliveredIDsPathEnv, "")
			root := t.TempDir()
			workspace := filepath.Join(root, "workspace")
			if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(workspace, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(workspace, ".aw"), []byte("invalid directory layout"), 0600); err != nil {
				t.Fatal(err)
			}
			messages, err := operation.run(workspace)
			if len(messages) != 0 {
				t.Fatal("unreadable workspace admitted messages")
			}
			if err == nil || !strings.Contains(err.Error(), "Repair the workspace before retrying") {
				t.Fatalf("marker read failure became a different store: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, ".aw", DeliveredIDsFileName)); !os.IsNotExist(err) {
				t.Fatalf("marker failure affected parent receipts: %v", err)
			}
		})
	}
}

func TestMalformedDeliveryReceiptEntryRefusesFiltering(t *testing.T) {
	cases := []struct {
		name    string
		entries map[string]string
	}{
		{name: "invalid timestamp", entries: map[string]string{"accepted-message": "not-a-time"}},
		{name: "empty identifier", entries: map[string]string{"": time.Now().UTC().Format(time.RFC3339Nano)}},
		{name: "null object", entries: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "receipts.json")
			t.Setenv(DeliveredIDsPathEnv, path)
			data, err := json.Marshal(tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			messages, err := FilterDeliveredMessagesForDir(t.TempDir(), []awid.ChatMessage{{MessageID: "accepted-message"}})
			if err == nil || len(messages) != 0 || !strings.Contains(err.Error(), "Repair or remove") {
				t.Fatalf("malformed receipt became empty state: messages=%v err=%v", messages, err)
			}
			if err := SaveDeliveredIDsForDir(t.TempDir(), []string{"next-message"}); err == nil || !strings.Contains(err.Error(), "Repair or remove") {
				t.Fatalf("writer replaced unreadable receipt state: %v", err)
			}
			stored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored, data) {
				t.Fatal("failed receipt read changed stored deliveries")
			}
		})
	}
}

func TestDanglingWorkspaceMarkerDoesNotSelectParentReceipts(t *testing.T) {
	t.Setenv(DeliveredIDsPathEnv, "")
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, ".aw"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-context", filepath.Join(workspace, ".aw", "context")); err != nil {
		t.Fatal(err)
	}
	if err := SaveDeliveredIDsForDir(root, []string{"parent-delivered"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveDeliveredIDsForDir(workspace, []string{"workspace-delivered"}); err != nil {
		t.Fatal(err)
	}
	workspaceIDs, err := LoadDeliveredIDsForDir(workspace)
	if err != nil {
		t.Fatal(err)
	}
	rootIDs, err := LoadDeliveredIDsForDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := workspaceIDs["parent-delivered"]; ok {
		t.Fatal("dangling marker selected parent receipts")
	}
	if _, ok := rootIDs["workspace-delivered"]; ok {
		t.Fatal("dangling marker redirected a receipt write")
	}
}

func TestDeliveryReceiptExpiryAndExplicitOverrideRemainUsable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".aw"), []byte("unused layout under explicit override"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "receipts.json")
	t.Setenv(DeliveredIDsPathEnv, path)
	ids, err := LoadDeliveredIDsForDir(root)
	if err != nil || len(ids) != 0 {
		t.Fatalf("missing receipt store is not empty: %v, %v", ids, err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	ids, err = LoadDeliveredIDsForDir(root)
	if err != nil || len(ids) != 0 {
		t.Fatalf("empty receipt object is not empty: %v, %v", ids, err)
	}
	now := time.Now()
	entries := map[string]string{"expired": now.Add(-2 * deliveredIDsTTL).UTC().Format(time.RFC3339Nano), "accepted": now.UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	messages, err := FilterDeliveredMessagesForDir(root, []awid.ChatMessage{{MessageID: "expired"}, {MessageID: "accepted"}, {MessageID: "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].MessageID != "expired" || messages[1].MessageID != "new" {
		t.Fatalf("valid expiry or override changed: %v", messages)
	}
	if err := SaveDeliveredIDsForDir(root, []string{"new"}); err != nil {
		t.Fatal(err)
	}
	ids, err = LoadDeliveredIDsForDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids["new"]; !ok {
		t.Fatal("explicit receipt store did not retain new delivery")
	}
}

func TestDeliveryReceiptAbsentMarkersUseGitRootAndExplicitWorkspaceWins(t *testing.T) {
	t.Setenv(DeliveredIDsPathEnv, "")
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	for _, dir := range []string{filepath.Join(root, ".git"), workspace} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := SaveDeliveredIDsForDir(workspace, []string{"root-message"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".aw", DeliveredIDsFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(workspace, ".aw"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".aw", "context"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SaveDeliveredIDsForDir(workspace, []string{"workspace-message"}); err != nil {
		t.Fatal(err)
	}
	workspaceIDs, err := LoadDeliveredIDsForDir(workspace)
	if err != nil {
		t.Fatal(err)
	}
	rootIDs, err := LoadDeliveredIDsForDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := workspaceIDs["root-message"]; ok {
		t.Fatal("explicit workspace loaded parent receipt")
	}
	if _, ok := rootIDs["workspace-message"]; ok {
		t.Fatal("parent loaded explicit workspace receipt")
	}
	if _, ok := workspaceIDs["workspace-message"]; !ok {
		t.Fatal("explicit workspace receipt missing")
	}
}
