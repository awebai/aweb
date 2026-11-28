package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const interactionLogFileName = "interaction-log.jsonl"

const (
	interactionKindUser    = "user"
	interactionKindAgent   = "agent"
	interactionKindChatIn  = "chat_in"
	interactionKindChatOut = "chat_out"
	interactionKindMailIn  = "mail_in"
	interactionKindMailOut = "mail_out"
)

type InteractionEntry struct {
	Timestamp      string `json:"ts"`
	Kind           string `json:"kind"`
	MessageID      string `json:"message_id,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	ConversationID string `json:"conversation_id,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	Subject        string `json:"subject,omitempty"`
	Text           string `json:"text,omitempty"`
}

func interactionLogRoot(startDir string) string {
	dir := filepath.Clean(startDir)
	for {
		for _, marker := range []string{filepath.Join(".aw", "context"), filepath.Join(".aw", "workspace.yaml"), ".git"} {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Clean(startDir)
		}
		dir = parent
	}
}

func interactionLogPath(startDir string) string {
	root := interactionLogRoot(startDir)
	return filepath.Join(root, ".aw", interactionLogFileName)
}

func appendInteractionLogForDir(startDir string, policy localLogPolicy, entry *InteractionEntry) {
	if entry == nil {
		return
	}
	if strings.TrimSpace(entry.Timestamp) == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(entry.Text) == "" && strings.TrimSpace(entry.Subject) == "" {
		return
	}

	path := interactionLogPath(startDir)
	if interactionEntryExists(path, entry.Kind, entry.MessageID) {
		return
	}
	line, err := json.Marshal(entry)
	if err != nil {
		debugLog("interaction-log: marshal: %v", err)
		return
	}
	if err := appendLocalLogLine(path, policy, line, interactionLogLineTag); err != nil {
		debugLog("interaction-log: %v", err)
	}
}

func appendInteractionLogForCWD(policy localLogPolicy, entry *InteractionEntry) {
	wd, err := os.Getwd()
	if err != nil {
		debugLog("interaction-log: getwd: %v", err)
		return
	}
	appendInteractionLogForDir(wd, policy, entry)
}

// interactionLogTag is the visible tag of a sealed interaction-log line: it
// lets the agent skip a message it already logged without reading the log,
// and reveals only whether a given message id was logged.
func interactionLogTag(kind, messageID string) string {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("aweb.interaction-log/1\n" + kind + "\n" + messageID))
	return hex.EncodeToString(sum[:])
}

func interactionLogLineTag(line []byte) string {
	var entry InteractionEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return ""
	}
	return interactionLogTag(entry.Kind, entry.MessageID)
}

func interactionEntryExists(path, kind, messageID string) bool {
	tag := interactionLogTag(kind, messageID)
	if tag == "" {
		return false
	}
	lines, err := readLocalLogLines(path, 200)
	if err != nil {
		return false
	}
	for _, line := range lines {
		if sealed := sealedLogLineOf(line); sealed != nil {
			if sealed.Tag == tag {
				return true
			}
			continue
		}
		if interactionLogLineTag(line) == tag {
			return true
		}
	}
	return false
}

func formatInteractionEntry(entry InteractionEntry) string {
	text := summarizeInteractionText(entry.Text, 140)
	switch entry.Kind {
	case interactionKindUser:
		return fmt.Sprintf("> %s", text)
	case interactionKindAgent:
		return text
	case interactionKindChatIn:
		return fmt.Sprintf("%s: %s", interactionCommLabel("from", interactionParty(entry.From, "someone"), "chat"), text)
	case interactionKindChatOut:
		return fmt.Sprintf("%s: %s", interactionCommLabel("to", interactionParty(entry.To, "someone"), "chat"), text)
	case interactionKindMailIn:
		if subject := strings.TrimSpace(entry.Subject); subject != "" {
			return fmt.Sprintf("%s: %s — %s", interactionCommLabel("from", interactionParty(entry.From, "someone"), "mail"), subject, text)
		}
		return fmt.Sprintf("%s: %s", interactionCommLabel("from", interactionParty(entry.From, "someone"), "mail"), text)
	case interactionKindMailOut:
		if subject := strings.TrimSpace(entry.Subject); subject != "" {
			return fmt.Sprintf("%s: %s — %s", interactionCommLabel("to", interactionParty(entry.To, "someone"), "mail"), subject, text)
		}
		return fmt.Sprintf("%s: %s", interactionCommLabel("to", interactionParty(entry.To, "someone"), "mail"), text)
	default:
		return text
	}
}

func summarizeInteractionText(text string, limit int) string {
	text = strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if text == "" {
		return ""
	}
	runes := []rune(text)
	if limit > 0 && len(runes) > limit {
		return string(runes[:limit-1]) + "…"
	}
	return text
}

func interactionParty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

// interactionCommLabel heads a chat or mail log line: "● from alice (mail)".
func interactionCommLabel(direction, party, channel string) string {
	return "● " + direction + " " + party + " (" + channel + ")"
}
