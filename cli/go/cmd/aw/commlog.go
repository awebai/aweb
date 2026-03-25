package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
)

// CommLogEntry is one line in the per-account communication log (JSONL).
type CommLogEntry struct {
	Timestamp    string `json:"ts"`
	Dir          string `json:"dir"`                    // "send" or "recv"
	Channel      string `json:"ch"`                     // "mail", "chat", "dm"
	MessageID    string `json:"msg_id,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Body         string `json:"body,omitempty"`
	FromDID      string `json:"from_did,omitempty"`
	ToDID        string `json:"to_did,omitempty"`
	FromStableID string `json:"from_stable_id,omitempty"`
	ToStableID   string `json:"to_stable_id,omitempty"`
	Signature    string `json:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
	Verification string `json:"verification,omitempty"`
}

// commLogPath returns the JSONL log file path for an account.
func commLogPath(logsDir, accountName string) string {
	return filepath.Join(logsDir, accountName+".jsonl")
}

// defaultLogsDir returns ~/.config/aw/logs (or AW_CONFIG_PATH-relative).
func defaultLogsDir() string {
	p, err := awconfig.DefaultGlobalConfigPath()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(p), "logs")
}

// appendCommLog writes a single entry to the account's communication log.
// Best-effort: errors go to debugLog, never block communication.
func appendCommLog(logsDir, accountName string, entry *CommLogEntry) {
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		debugLog("commlog: mkdir %s: %v", logsDir, err)
		return
	}

	line, err := json.Marshal(entry)
	if err != nil {
		debugLog("commlog: marshal: %v", err)
		return
	}
	line = append(line, '\n')

	path := commLogPath(logsDir, accountName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		debugLog("commlog: open %s: %v", path, err)
		return
	}
	defer f.Close()

	if _, err := f.Write(line); err != nil {
		debugLog("commlog: write: %v", err)
	}
}
