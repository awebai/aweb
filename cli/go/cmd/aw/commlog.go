package main

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
)

// CommLogEntry is one line in the per-account communication log (JSONL).
type CommLogEntry struct {
	Timestamp      string `json:"ts"`
	Dir            string `json:"dir"` // "send" or "recv"
	Channel        string `json:"ch"`  // "mail", "chat", "dm"
	MessageID      string `json:"msg_id,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	ConversationID string `json:"conversation_id,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	Subject        string `json:"subject,omitempty"`
	Body           string `json:"body,omitempty"`
	FromDID        string `json:"from_did,omitempty"`
	ToDID          string `json:"to_did,omitempty"`
	FromStableID   string `json:"from_stable_id,omitempty"`
	ToStableID     string `json:"to_stable_id,omitempty"`
	Signature      string `json:"signature,omitempty"`
	SigningKeyID   string `json:"signing_key_id,omitempty"`
	Verification   string `json:"verification,omitempty"`
}

// commLogPath returns the JSONL log file path for an account.
func commLogPath(logsDir, accountName string) string {
	return filepath.Join(logsDir, accountName+".jsonl")
}

func commLogNameForSelection(sel *awconfig.Selection) string {
	if sel == nil {
		return "workspace"
	}
	candidates := []string{
		strings.TrimSpace(sel.StableID),
		strings.TrimSpace(sel.DID),
		selectionAddress(sel),
		strings.TrimSpace(sel.Alias),
		strings.TrimSpace(sel.WorkspaceID),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		return sanitizeKeyComponent(candidate)
	}
	return "workspace"
}

// defaultLogsDir returns ~/.config/aw/logs.
func defaultLogsDir() string {
	p, err := awconfig.DefaultLogsDir()
	if err != nil {
		return ""
	}
	return p
}

// appendCommLog writes a single entry to the account's communication log,
// sealed to the team's owner log key when one is installed.
// Best-effort: errors go to debugLog, never block communication.
func appendCommLog(logsDir, accountName string, policy localLogPolicy, entry *CommLogEntry) {
	line, err := json.Marshal(entry)
	if err != nil {
		debugLog("commlog: marshal: %v", err)
		return
	}
	if err := appendLocalLogLine(commLogPath(logsDir, accountName), policy, line, nil); err != nil {
		debugLog("commlog: %v", err)
	}
}
