package chat

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/atomicfile"
)

const (
	DeliveredIDsFileName = "chat-delivered-ids.json"
	deliveredIDsTTL      = 10 * time.Minute
	DeliveredIDsPathEnv  = "AW_CHAT_DELIVERED_IDS_PATH"
)

type deliveredIDsFile map[string]string

// deliveredIDsRoot keeps receipt scope stable on lookup failures; only absent
// markers permit a parent search (docs/receiving-events.md, “What the native channel does,” line 173).
func deliveredIDsRoot(startDir string) (string, error) {
	directory := filepath.Clean(startDir)
	for _, name := range []string{"context", "workspace.yaml"} {
		exists, err := receiptStoreMarkerExists(filepath.Join(directory, ".aw", name))
		if err != nil {
			return "", err
		}
		if exists {
			return directory, nil
		}
	}
	root, err := findGitRoot(directory)
	if err != nil {
		return "", err
	}
	if root != "" {
		return root, nil
	}
	return directory, nil
}

func deliveredIDsPath(startDir string) (string, error) {
	if override := strings.TrimSpace(os.Getenv(DeliveredIDsPathEnv)); override != "" {
		return filepath.Clean(override), nil
	}
	root, err := deliveredIDsRoot(startDir)
	if err != nil {
		return "", fmt.Errorf("locate chat delivery receipts: %w. Repair the workspace before retrying", err)
	}
	return filepath.Join(root, ".aw", DeliveredIDsFileName), nil
}

// LoadDeliveredIDs reads unexpired receipt IDs for the current process directory.
// A missing store is empty; a corrupt cache is quarantined and reset with a warning.
func LoadDeliveredIDs() (map[string]struct{}, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return LoadDeliveredIDsForDir(wd)
}

// LoadDeliveredIDsForDir reads receipt IDs for startDir, honoring
// DeliveredIDsPathEnv. Receipts older than ten minutes are excluded.
func LoadDeliveredIDsForDir(startDir string) (map[string]struct{}, error) {
	path, err := deliveredIDsPath(startDir)
	if err != nil {
		return nil, err
	}
	entries, err := loadDeliveredIDTimesWithRecovery(path, time.Now())
	if err != nil {
		return nil, err
	}
	ids := make(map[string]struct{}, len(entries))
	for id := range entries {
		ids[id] = struct{}{}
	}
	return ids, nil
}

// SaveDeliveredIDs records accepted message IDs for the process directory.
// It merges concurrent updates and expires old receipts under the store lock.
func SaveDeliveredIDs(ids []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	return SaveDeliveredIDsForDir(wd, ids)
}

// SaveDeliveredIDsForDir atomically merges accepted IDs into startDir's receipt
// store, honoring DeliveredIDsPathEnv and preserving concurrent writers.
func SaveDeliveredIDsForDir(startDir string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now()
	path, err := deliveredIDsPath(startDir)
	if err != nil {
		return err
	}

	return withDeliveryReceiptLock(path, func() error {
		existing, err := loadOrQuarantineDeliveredIDTimes(path, now)
		if err != nil {
			return err
		}
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id != "" {
				existing[id] = now
			}
		}
		return writeDeliveredIDs(path, existing)
	})
}

// withDeliveryReceiptLock serializes merges and cache recovery so recovering a
// corrupt cache cannot discard a concurrent accepted delivery
// (docs/receiving-events.md, “What the native channel does,” line 173). Kernel locks are released on process exit.
func withDeliveryReceiptLock(path string, operation func() error) (err error) {
	lock, err := awconfig.LockExclusive(path + ".lock")
	if err != nil {
		return fmt.Errorf("lock chat delivery receipt cache %q: %w. Repair the cache directory before retrying", path, err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("release chat delivery receipt lock: %w. Retry the receipt operation", closeErr))
		}
	}()
	return operation()
}

// DeliveredMessageIDs returns unique, nonempty, trimmed message IDs in the
// order they first occur in messages. It does not write delivery receipts.
func DeliveredMessageIDs(messages []awid.ChatMessage) []string {
	if len(messages) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(messages))
	ids := make([]string, 0, len(messages))
	for _, msg := range messages {
		id := strings.TrimSpace(msg.MessageID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

// FilterDeliveredMessages filters for the process directory and leaves messages
// unchanged on a receipt-store read error.
// Deprecated: use FilterDeliveredMessagesForDir to receive failure diagnostics.
func FilterDeliveredMessages(messages []awid.ChatMessage) []awid.ChatMessage {
	wd, err := os.Getwd()
	if err != nil {
		return messages
	}
	filtered, err := FilterDeliveredMessagesForDir(wd, messages)
	if err != nil {
		return messages
	}
	return filtered
}

// FilterDeliveredMessagesForDir binds suppression to the selected workspace and
// reports workspace lookup failures. Corrupt caches are quarantined and reset,
// with a warning that messages may be shown again.
// docs/receiving-events.md, “What the native channel does,” line 173 defines per-workspace suppression.
func FilterDeliveredMessagesForDir(startDir string, messages []awid.ChatMessage) ([]awid.ChatMessage, error) {
	delivered, err := LoadDeliveredIDsForDir(startDir)
	if err != nil {
		return nil, err
	}
	filtered := make([]awid.ChatMessage, 0, len(messages))
	for _, msg := range messages {
		if _, ok := delivered[strings.TrimSpace(msg.MessageID)]; ok {
			continue
		}
		filtered = append(filtered, msg)
	}
	return filtered, nil
}

// loadDeliveredIDTimesWithRecovery leaves missing and expired receipts empty.
// This is a ten-minute suppression cache, not proof of delivery authority: a
// corrupt cache degrades to possible duplicate presentation instead of blocking
// chat. Workspace lookup failures still refuse (docs/receiving-events.md, “What the native channel does,” line 173).
func loadDeliveredIDTimesWithRecovery(path string, now time.Time) (map[string]time.Time, error) {
	entries, err := loadDeliveredIDTimes(path, now)
	if err == nil {
		return entries, nil
	}
	err = withDeliveryReceiptLock(path, func() error {
		var readErr error
		entries, readErr = loadOrQuarantineDeliveredIDTimes(path, now)
		return readErr
	})
	return entries, err
}

// loadOrQuarantineDeliveredIDTimes runs under the receipt lock. It re-reads
// before recovery so another writer's completed repair is preserved.
func loadOrQuarantineDeliveredIDTimes(path string, now time.Time) (map[string]time.Time, error) {
	entries, readErr := loadDeliveredIDTimes(path, now)
	if readErr == nil {
		return entries, nil
	}
	quarantined, err := quarantineDeliveryReceiptStore(path, now)
	if err != nil {
		return nil, errors.Join(readErr, err)
	}
	entries = make(map[string]time.Time)
	if err := writeDeliveredIDs(path, entries); err != nil {
		return nil, fmt.Errorf("receipt cache quarantined at %q but reset failed: %w. Repair the cache directory before retrying", quarantined, err)
	}
	if _, err := fmt.Fprintf(os.Stderr, "WARNING: chat delivery receipt cache %q could not be read (%q); quarantined at %q and reset. Messages may be shown again; inspect the quarantined cache if needed.\n", path, readErr.Error(), quarantined); err != nil {
		// A supervisor may close stderr. The quarantine retains the record,
		// so a failed best-effort warning must not stop chat after recovery.
		return entries, nil
	}
	return entries, nil
}

func quarantineDeliveryReceiptStore(path string, now time.Time) (string, error) {
	directory, err := os.MkdirTemp(filepath.Dir(path), filepath.Base(path)+".quarantine-"+now.UTC().Format("20060102T150405.000000000Z")+"-")
	if err != nil {
		return "", fmt.Errorf("create receipt cache quarantine: %w. Repair the cache directory before retrying", err)
	}
	quarantined := filepath.Join(directory, filepath.Base(path))
	if err := os.Rename(path, quarantined); err != nil {
		if removeErr := os.Remove(directory); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove empty receipt quarantine %q: %w", directory, removeErr))
		}
		return "", fmt.Errorf("quarantine receipt cache %q: %w. Repair the cache directory before retrying", path, err)
	}
	return quarantined, nil
}

// loadDeliveredIDTimes parses the cache without changing it. Its callers own
// locked recovery; expiry alone never requires quarantine.
func loadDeliveredIDTimes(path string, now time.Time) (map[string]time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]time.Time{}, nil
		}
		return nil, err
	}
	var raw deliveredIDsFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("delivery receipt store must be a JSON object")
	}
	active := make(map[string]time.Time, len(raw))
	cutoff := now.Add(-deliveredIDsTTL)
	for id, ts := range raw {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("delivery receipt identifier is empty")
		}
		seenAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(ts))
		if err != nil {
			return nil, fmt.Errorf("delivery receipt %q timestamp: %w", id, err)
		}
		if seenAt.Before(cutoff) {
			continue
		}
		active[id] = seenAt
	}
	return active, nil
}

func writeDeliveredIDs(path string, entries map[string]time.Time) error {
	payload := make(deliveredIDsFile, len(entries))
	for id, seenAt := range entries {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		payload[id] = seenAt.UTC().Format(time.RFC3339Nano)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	return atomicfile.Options{Mode: 0o600, ParentMode: 0o700}.Write(path, data)
}

func receiptStoreMarkerExists(path string) (bool, error) {
	// The marker itself selects scope; a dangling target must not redirect
	// receipts to a parent workspace (docs/receiving-events.md, “What the native channel does,” line 173).
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("inspect receipt-store marker %q: %w", path, err)
}

func findGitRoot(startDir string) (string, error) {
	directory := filepath.Clean(startDir)
	for {
		exists, err := receiptStoreMarkerExists(filepath.Join(directory, ".git"))
		if err != nil {
			return "", err
		}
		if exists {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", nil
		}
		directory = parent
	}
}
