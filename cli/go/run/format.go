package run

import (
	"fmt"
	"sort"
	"strings"
)

type presenterState struct {
	lastWasText              bool
	lastWasStructured        bool
	lastTextEndedWithNewline bool
	rawLineOpen              bool
	rawLineLabel             string
}

func formatDone(event *Event) string {
	label := "done"
	if event != nil && event.IsError {
		label = "error"
	}
	parts := []string{label}
	duration := event.DurationMS
	if duration > 0 {
		parts = append(parts, fmt.Sprintf("%.1fs", float64(duration)/1000.0))
	}
	if event.CostUSD != nil {
		parts = append(parts, fmt.Sprintf("$%.4f", *event.CostUSD))
	}
	if event != nil && event.IsError && strings.TrimSpace(event.Text) != "" {
		parts = append(parts, truncateText(event.Text, 160))
	}
	return strings.Join(parts, "  ")
}

func formatToolCallLines(call ToolCall) []string {
	if line, ok := formatCoordinationToolCall(call); ok {
		return []string{line}
	}
	args := formatToolSummaryArgs(call.Input)
	lines := formatToolSummaryLines(call.Name, args)
	if description := formatToolDescription(call.Input); description != "" {
		lines = append(lines, "  "+description)
	}
	return lines
}

func formatToolResultLines(text string) []string {
	lines := trimOuterBlankLines(strings.Split(strings.ReplaceAll(text, "\r", ""), "\n"))
	if len(lines) == 0 {
		return nil
	}

	const maxLines = 6
	formatted := make([]string, 0, min(len(lines), maxLines)+1)
	for i, line := range lines {
		if i >= maxLines {
			formatted = append(formatted, fmt.Sprintf("    ... +%d lines", len(lines)-maxLines))
			break
		}
		formatted = append(formatted, "    "+truncateLine(line, 150))
	}
	return formatted
}

func formatCoordinationToolCall(call ToolCall) (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(call.Name), "Bash") {
		return "", false
	}
	command, _ := call.Input["command"].(string)
	if command == "" {
		return "", false
	}
	return formatAWCoordinationCommand(command)
}

func formatAWCoordinationCommand(command string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) < 3 || fields[0] != "aw" {
		return "", false
	}

	switch fields[1] {
	case "mail":
		if fields[2] != "send" {
			return "", false
		}
		alias := findFlagValue(fields[3:], "--to")
		if alias == "" {
			return "", false
		}
		return FormatCommLabel("to", alias, "mail"), true
	case "chat":
		switch fields[2] {
		case "send-and-wait", "send-and-leave":
			alias := firstNonFlag(fields[3:])
			if alias == "" {
				return "", false
			}
			return FormatCommLabel("to", alias, "chat"), true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func FormatCommLabel(direction string, alias string, channel string) string {
	alias = strings.TrimSpace(alias)
	channel = strings.TrimSpace(channel)
	direction = strings.TrimSpace(direction)
	label := "•"
	if direction != "" {
		label += " " + direction
	}
	if alias != "" {
		label += " " + alias
	}
	if channel != "" {
		label += " (" + channel + ")"
	}
	return label
}

func isIncomingCommDisplay(display string) bool {
	return strings.HasPrefix(strings.TrimSpace(display), "• from ")
}

func findFlagValue(fields []string, flag string) string {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == flag {
			return fields[i+1]
		}
	}
	return ""
}

func firstNonFlag(fields []string) string {
	for _, field := range fields {
		if !strings.HasPrefix(field, "-") {
			return field
		}
	}
	return ""
}

func formatToolSummaryLines(name string, args []string) []string {
	prefix := ">_ "
	name = strings.TrimSpace(name)
	if name != "" && !strings.EqualFold(name, "Bash") {
		prefix += name + " "
	}
	if len(args) == 0 {
		return []string{strings.TrimRight(prefix, " ")}
	}

	indent := strings.Repeat(" ", len(prefix))
	lines := make([]string, 0, len(args))
	for i, arg := range args {
		if i == 0 {
			lines = append(lines, prefix+arg)
			continue
		}
		lines = append(lines, indent+arg)
	}
	return lines
}

func formatToolDescription(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}
	description, _ := data["description"].(string)
	return truncateText(description, 160)
}

func formatToolSummaryArgs(data map[string]any) []string {
	if len(data) == 0 {
		return nil
	}

	keys := make([]string, 0, len(data))
	for key := range data {
		if key == "description" {
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.SliceStable(keys, func(i, j int) bool {
		leftRank := toolSummaryKeyRank(keys[i])
		rightRank := toolSummaryKeyRank(keys[j])
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return keys[i] < keys[j]
	})

	args := make([]string, 0, len(keys))
	for index, key := range keys {
		value := data[key]
		omitKey := index == 0 && toolSummaryCanOmitKey(key, value)
		formattedValue := formatToolSummaryValue(value, omitKey)
		if omitKey {
			args = append(args, formattedValue)
			continue
		}
		args = append(args, fmt.Sprintf("%s=%s", key, formattedValue))
	}
	return args
}

func toolSummaryCanOmitKey(key string, value any) bool {
	if _, ok := value.(string); !ok {
		return false
	}
	switch key {
	case "command", "cmd", "query", "path", "url":
		return true
	default:
		return false
	}
}

func toolSummaryKeyRank(key string) int {
	switch key {
	case "command":
		return 0
	case "cmd":
		return 1
	case "query":
		return 2
	case "file_path":
		return 3
	case "path":
		return 4
	case "url":
		return 5
	default:
		return 10
	}
}

func formatToolSummaryValue(value any, rawString bool) string {
	switch typed := value.(type) {
	case string:
		if rawString {
			return truncateText(typed, 160)
		}
		return fmt.Sprintf("%q", truncateText(typed, 160))
	default:
		return truncateText(fmt.Sprintf("%v", typed), 160)
	}
}

func truncateText(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func truncateLine(s string, max int) string {
	runes := []rune(strings.TrimRight(s, " "))
	if len(runes) <= max {
		return string(runes)
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

func trimOuterBlankLines(lines []string) []string {
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	end := len(lines)
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	return lines[start:end]
}
