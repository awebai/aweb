package chat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
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

func LoadDeliveredIDs() (map[string]struct{}, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return LoadDeliveredIDsForDir(wd)
}

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

func SaveDeliveredIDs(ids []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	return SaveDeliveredIDsForDir(wd, ids)
}

func SaveDeliveredIDsForDir(startDir string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now()
	path := deliveredIDsPath(startDir)

	// Serialize the whole read-merge-write. Without it, concurrent writers each
	// merge onto a snapshot taken before the others wrote and the last rename
	// wins — and the loss is SILENT, because every writer still reports success.
	// A dropped mark makes an already-delivered message look new, so it is
	// dispatched again: a duplicate model invocation or a repeated human-visible
	// message (default-aajc.10).
	//
	// Contention here is ordinary: the `aw run` wake loop and any `aw chat`
	// command in the same worktree write this same file. Only Go writes it — the
	// Node channel uses channel-delivered-ids.json — so a Go-side lock is
	// sufficient. flock is released by the kernel when the process dies, so an
	// abandoned lock cannot wedge the store.
	unlock, err := awconfig.LockExclusive(path + ".lock")
	if err != nil {
		return err
	}
	defer func() { _ = unlock.Close() }()

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

func FilterDeliveredMessages(messages []awid.ChatMessage) []awid.ChatMessage {
	if len(messages) == 0 {
		return nil
	}
	delivered, err := LoadDeliveredIDs()
	if err != nil || len(delivered) == 0 {
		return messages
	}
	filtered := make([]awid.ChatMessage, 0, len(messages))
	for _, msg := range messages {
		id := strings.TrimSpace(msg.MessageID)
		if id != "" {
			if _, ok := delivered[id]; ok {
				continue
			}
		}
		filtered = append(filtered, msg)
	}
	return filtered
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

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "chat-delivered-ids-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
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
