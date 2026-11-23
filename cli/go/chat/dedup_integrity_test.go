package chat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
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

func TestCorruptDeliveryReceiptCacheDoesNotBlockFiltering(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{name: "invalid timestamp", data: []byte(`{"accepted-message":"not-a-time"}`)},
		{name: "empty identifier", data: []byte(`{"":"2026-11-19T00:00:00Z"}`)},
		{name: "null object", data: []byte(`null`)},
		{name: "malformed JSON", data: []byte(`{"accepted-message":`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "receipts.json")
			t.Setenv(DeliveredIDsPathEnv, path)
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			warnings := recordDeliveryReceiptDiagnostics(t, func() {
				messages, err := FilterDeliveredMessagesForDir(t.TempDir(), []awid.ChatMessage{{MessageID: "accepted-message"}})
				if err != nil || len(messages) != 1 || messages[0].MessageID != "accepted-message" {
					t.Fatalf("corrupt cache blocked filtering: messages=%v err=%v", messages, err)
				}
				ids, err := LoadDeliveredIDsForDir(t.TempDir())
				if err != nil || len(ids) != 0 {
					t.Fatalf("reset cache not empty: %v, %v", ids, err)
				}
				if err := SaveDeliveredIDsForDir(t.TempDir(), []string{"next-message"}); err != nil {
					t.Fatal(err)
				}
			})
			quarantines, err := filepath.Glob(path + ".quarantine-*")
			if err != nil {
				t.Fatal(err)
			}
			if len(quarantines) != 1 {
				t.Fatalf("quarantines=%v", quarantines)
			}
			preserved := filepath.Join(quarantines[0], filepath.Base(path))
			stored, err := os.ReadFile(preserved)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored, tc.data) {
				t.Fatal("quarantine lost corrupt receipt bytes")
			}
			if strings.Count(warnings, "WARNING:") != 1 || !strings.Contains(warnings, path) || !strings.Contains(warnings, preserved) || !strings.Contains(warnings, "Messages may be shown again") {
				t.Fatalf("missing single actionable quarantine warning: %q", warnings)
			}
			ids, err := LoadDeliveredIDsForDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if len(ids) != 1 {
				t.Fatalf("reset store lost next delivery: %v", ids)
			}
			if _, ok := ids["next-message"]; !ok {
				t.Fatalf("reset store missing new receipt: %v", ids)
			}
		})
	}
}

func TestClosedStderrDoesNotBlockReceiptCacheRecovery(t *testing.T) {
	workspace := t.TempDir()
	path := filepath.Join(workspace, "receipts.json")
	t.Setenv(DeliveredIDsPathEnv, path)
	corrupt := []byte(`{"accepted-message":"not-a-time"}`)
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	closedOutput, err := os.CreateTemp(t.TempDir(), "closed-stderr-")
	if err != nil {
		t.Fatal(err)
	}
	if err := closedOutput.Close(); err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	t.Cleanup(func() { os.Stderr = original })
	os.Stderr = closedOutput

	messages, err := FilterDeliveredMessagesForDir(workspace, []awid.ChatMessage{{MessageID: "accepted-message"}})
	if err != nil || len(messages) != 1 || messages[0].MessageID != "accepted-message" {
		t.Fatalf("closed diagnostic output blocked cache recovery: messages=%v err=%v", messages, err)
	}
	quarantines, err := filepath.Glob(path + ".quarantine-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(quarantines) != 1 {
		t.Fatalf("quarantines=%v", quarantines)
	}
	data, err := os.ReadFile(filepath.Join(quarantines[0], filepath.Base(path)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, corrupt) {
		t.Fatal("closed stderr lost the quarantine record")
	}
	fresh, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipts map[string]string
	if err := json.Unmarshal(fresh, &receipts); err != nil {
		t.Fatal(err)
	}
	if receipts == nil || len(receipts) != 0 {
		t.Fatalf("cache was not reset to an empty object: %q", fresh)
	}
	if err := SaveDeliveredIDsForDir(workspace, []string{"next-message"}); err != nil {
		t.Fatal(err)
	}
	ids, err := LoadDeliveredIDsForDir(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("reset cache lost next delivery: %v", ids)
	}
	if _, ok := ids["next-message"]; !ok {
		t.Fatalf("next receipt missing: %v", ids)
	}
}

func TestCorruptDeliveryReceiptCacheRecoversBeforeWriterMerge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.json")
	t.Setenv(DeliveredIDsPathEnv, path)
	corrupt := []byte(`not a receipt object`)
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	warnings := recordDeliveryReceiptDiagnostics(t, func() {
		if err := SaveDeliveredIDsForDir(t.TempDir(), []string{"accepted-message"}); err != nil {
			t.Fatal(err)
		}
	})
	ids, err := LoadDeliveredIDsForDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("writer did not merge into reset cache: %v", ids)
	}
	if _, ok := ids["accepted-message"]; !ok {
		t.Fatalf("missing accepted receipt: %v", ids)
	}
	quarantines, err := filepath.Glob(path + ".quarantine-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(quarantines) != 1 {
		t.Fatalf("quarantines=%v", quarantines)
	}
	data, err := os.ReadFile(filepath.Join(quarantines[0], filepath.Base(path)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, corrupt) || strings.Count(warnings, "WARNING:") != 1 {
		t.Fatalf("lost quarantine or diagnostic: data=%q warnings=%q", data, warnings)
	}
}

func TestUnreadableDeliveryReceiptCacheIsQuarantined(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.json")
	t.Setenv(DeliveredIDsPathEnv, path)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	evidence := []byte("unreadable cache directory retained")
	if err := os.WriteFile(filepath.Join(path, "evidence"), evidence, 0600); err != nil {
		t.Fatal(err)
	}
	warnings := recordDeliveryReceiptDiagnostics(t, func() {
		messages, err := FilterDeliveredMessagesForDir(t.TempDir(), []awid.ChatMessage{{MessageID: "new"}})
		if err != nil || len(messages) != 1 || messages[0].MessageID != "new" {
			t.Fatalf("unreadable cache blocked filtering: %v %v", messages, err)
		}
	})
	quarantines, err := filepath.Glob(path + ".quarantine-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(quarantines) != 1 {
		t.Fatalf("quarantines=%v", quarantines)
	}
	data, err := os.ReadFile(filepath.Join(quarantines[0], filepath.Base(path), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, evidence) || strings.Count(warnings, "WARNING:") != 1 {
		t.Fatalf("cache evidence or warning missing: %q %q", data, warnings)
	}
	ids, err := LoadDeliveredIDsForDir(t.TempDir())
	if err != nil || len(ids) != 0 {
		t.Fatalf("replacement cache not empty: %v %v", ids, err)
	}
}

func TestConcurrentReceiptRecoveryPreservesAcceptedDeliveries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.json")
	workspace := t.TempDir()
	t.Setenv(DeliveredIDsPathEnv, path)
	if err := os.WriteFile(path, []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	const writers = 12
	warnings := recordDeliveryReceiptDiagnostics(t, func() {
		start := make(chan struct{})
		results := make(chan error, writers)
		for index := 0; index < writers; index++ {
			go func(index int) {
				<-start
				_, err := FilterDeliveredMessagesForDir(workspace, []awid.ChatMessage{{MessageID: "unseen"}})
				if err == nil {
					err = SaveDeliveredIDsForDir(workspace, []string{fmt.Sprintf("accepted-%d", index)})
				}
				results <- err
			}(index)
		}
		close(start)
		for index := 0; index < writers; index++ {
			if err := <-results; err != nil {
				t.Error(err)
			}
		}
	})
	ids, err := LoadDeliveredIDsForDir(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != writers {
		t.Fatalf("recovery lost accepted deliveries: %v", ids)
	}
	for index := 0; index < writers; index++ {
		if _, ok := ids[fmt.Sprintf("accepted-%d", index)]; !ok {
			t.Fatalf("missing writer %d", index)
		}
	}
	quarantines, err := filepath.Glob(path + ".quarantine-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(quarantines) != 1 || strings.Count(warnings, "WARNING:") != 1 {
		t.Fatalf("recovery was not serialized: quarantines=%v warnings=%q", quarantines, warnings)
	}
}

// A regular file records diagnostics without a pipe-capacity dependency.
func recordDeliveryReceiptDiagnostics(t *testing.T, operation func()) string {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "receipt-diagnostics-")
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = output
	defer func() {
		os.Stderr = original
		if err := output.Close(); err != nil {
			t.Error(err)
		}
	}()
	operation()
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
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
