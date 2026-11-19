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

func deliveredIDsRoot(startDir string) string {
	for _, name := range []string{"context", "workspace.yaml"} {
		if path := filepath.Join(filepath.Clean(startDir), ".aw", name); fileExists(path) {
			return filepath.Clean(startDir)
		}
	}
	if root := findGitRoot(startDir); root != "" {
		return root
	}
	return filepath.Clean(startDir)
}

func deliveredIDsPath(startDir string) string {
	if override := strings.TrimSpace(os.Getenv(DeliveredIDsPathEnv)); override != "" {
		return filepath.Clean(override)
	}
	return filepath.Join(deliveredIDsRoot(startDir), ".aw", DeliveredIDsFileName)
}

// LoadDeliveredIDs reads unexpired receipt IDs for the current process directory.
// A missing store is empty; unreadable or malformed state returns an error.
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
	entries, err := loadDeliveredIDTimes(deliveredIDsPath(startDir), time.Now())
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
func SaveDeliveredIDsForDir(startDir string, ids []string) (err error) {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now()
	path := deliveredIDsPath(startDir)

	// Serialize receipt updates so concurrent writers retain each other's
	// accepted deliveries (docs/receiving-events.md:174). Kernel-released
	// locks keep a crashed writer from wedging later receipt updates.
	unlock, err := awconfig.LockExclusive(path + ".lock")
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := unlock.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("release chat delivery receipt lock: %w. Retry the receipt update", closeErr))
		}
	}()

	existing, err := loadDeliveredIDTimes(path, now)
	if err != nil {
		return err
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		existing[id] = now
	}
	return writeDeliveredIDs(path, existing)
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

// FilterDeliveredMessages retains the released best-effort, process-directory
// API. Deprecated: use FilterDeliveredMessagesForDir to handle receipt errors.
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
// reports unreadable state rather than treating it as an empty receipt store.
// docs/receiving-events.md:174 defines per-workspace suppression.
func FilterDeliveredMessagesForDir(startDir string, messages []awid.ChatMessage) ([]awid.ChatMessage, error) {
	delivered, err := LoadDeliveredIDsForDir(startDir)
	if err != nil {
		return nil, fmt.Errorf("read chat delivery receipts: %w. Repair or remove %s before retrying", err, deliveredIDsPath(startDir))
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
	active := make(map[string]time.Time, len(raw))
	cutoff := now.Add(-deliveredIDsTTL)
	for id, ts := range raw {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		seenAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(ts))
		if err != nil {
			continue
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func findGitRoot(startDir string) string {
	dir := filepath.Clean(startDir)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
