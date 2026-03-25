package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/awebai/aw/awconfig"
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
	Timestamp string `json:"ts"`
	Kind      string `json:"kind"`
	MessageID string `json:"message_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Text      string `json:"text,omitempty"`
}

func interactionLogRoot(startDir string) string {
	if path, err := awconfig.FindWorktreeContextPath(startDir); err == nil {
		return filepath.Dir(filepath.Dir(path))
	}
	if path, err := awconfig.FindWorktreeWorkspacePath(startDir); err == nil {
		return filepath.Dir(filepath.Dir(path))
	}
	return filepath.Clean(startDir)
}

func interactionLogPath(startDir string) string {
	root := interactionLogRoot(startDir)
	return filepath.Join(root, ".aw", interactionLogFileName)
}

func appendInteractionLogForDir(startDir string, entry *InteractionEntry) {
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		debugLog("interaction-log: mkdir %s: %v", filepath.Dir(path), err)
		return
	}
	line, err := json.Marshal(entry)
	if err != nil {
		debugLog("interaction-log: marshal: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		debugLog("interaction-log: open %s: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		debugLog("interaction-log: write: %v", err)
	}
}

func appendInteractionLogForCWD(entry *InteractionEntry) {
	wd, err := os.Getwd()
	if err != nil {
		debugLog("interaction-log: getwd: %v", err)
		return
	}
	appendInteractionLogForDir(wd, entry)
}

func interactionEntryExists(path, kind, messageID string) bool {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return false
	}
	entries, err := readInteractionLog(path, 200)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.Kind == kind && entry.MessageID == messageID {
			return true
		}
	}
	return false
}

func readInteractionLog(path string, limit int) ([]InteractionEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []InteractionEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry InteractionEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries, nil
}

func formatInteractionRecap(entries []InteractionEntry, limit int) string {
	return formatInteractionRecapStyled(entries, limit, false, 0)
}

func formatInteractionRecapStyled(entries []InteractionEntry, limit int, ansi bool, width int) string {
	if len(entries) == 0 {
		return ""
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	var sb strings.Builder
	sb.WriteString("Recent interactions\n\n")
	for _, entry := range entries {
		line := strings.TrimSpace(formatInteractionEntry(entry))
		if line == "" {
			continue
		}
		if isInteractionComm(entry.Kind) && width > 0 {
			line = wrapInteractionCommLine(line, width)
		}
		switch {
		case entry.Kind == interactionKindUser:
			line = maybeBoldANSI(line, ansi)
		case isInteractionComm(entry.Kind):
			line = maybeBoldInteractionCommPrefixANSI(line, ansi)
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	return sb.String()
}

func formatInteractionEntry(entry InteractionEntry) string {
	text := summarizeInteractionText(entry.Text, 140)
	switch entry.Kind {
	case interactionKindUser:
		return fmt.Sprintf("> %s", text)
	case interactionKindAgent:
		return text
	case interactionKindChatIn:
		return fmt.Sprintf("<- %s (chat): %s", interactionParty(entry.From, "someone"), text)
	case interactionKindChatOut:
		return fmt.Sprintf("-> %s (chat): %s", interactionParty(entry.To, "someone"), text)
	case interactionKindMailIn:
		if subject := strings.TrimSpace(entry.Subject); subject != "" {
			return fmt.Sprintf("<- %s (mail): %s — %s", interactionParty(entry.From, "someone"), subject, text)
		}
		return fmt.Sprintf("<- %s (mail): %s", interactionParty(entry.From, "someone"), text)
	case interactionKindMailOut:
		if subject := strings.TrimSpace(entry.Subject); subject != "" {
			return fmt.Sprintf("-> %s (mail): %s — %s", interactionParty(entry.To, "someone"), subject, text)
		}
		return fmt.Sprintf("-> %s (mail): %s", interactionParty(entry.To, "someone"), text)
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

func maybeBoldANSI(text string, ansi bool) string {
	if !ansi || strings.TrimSpace(text) == "" {
		return text
	}
	return "\x1b[1m" + text + "\x1b[0m"
}

func maybeBoldInteractionCommPrefixANSI(text string, ansi bool) string {
	if !ansi || strings.TrimSpace(text) == "" {
		return text
	}
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return text
	}
	lines[0] = boldInteractionCommPrefix(lines[0], ansi)
	return strings.Join(lines, "\n")
}

func boldInteractionCommPrefix(line string, ansi bool) string {
	if !ansi {
		return line
	}
	if !strings.HasPrefix(line, "<- ") && !strings.HasPrefix(line, "-> ") {
		return line
	}
	rest := line[3:]
	aliasEnd := len(rest)
	for i, r := range rest {
		if r == ' ' || r == ':' {
			aliasEnd = i
			break
		}
	}
	return "\x1b[1m" + line[:3+aliasEnd] + "\x1b[0m" + line[3+aliasEnd:]
}

func isInteractionComm(kind string) bool {
	switch kind {
	case interactionKindChatIn, interactionKindChatOut, interactionKindMailIn, interactionKindMailOut:
		return true
	default:
		return false
	}
}

func wrapInteractionCommLine(line string, width int) string {
	if width <= 0 || utf8.RuneCountInString(line) <= width {
		return line
	}
	const continuationIndent = "   "
	parts := strings.SplitAfter(line, " ")
	if len(parts) == 0 {
		return line
	}

	lines := make([]string, 0, 4)
	current := ""
	for _, part := range parts {
		if current == "" {
			current = strings.TrimLeft(part, " ")
			continue
		}
		candidate := current + part
		if utf8.RuneCountInString(strings.TrimRight(candidate, " ")) <= width {
			current = candidate
			continue
		}
		lines = append(lines, strings.TrimRight(current, " "))
		current = continuationIndent + strings.TrimLeft(part, " ")
	}
	if strings.TrimSpace(current) != "" {
		lines = append(lines, strings.TrimRight(current, " "))
	}
	if len(lines) == 0 {
		return line
	}
	return strings.Join(lines, "\n")
}
