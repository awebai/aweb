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
	lastTextKind             DisplayKind
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

func formatToolCallDisplay(call ToolCall) []DisplayLine {
	if line, ok := formatCoordinationToolCall(call); ok {
		return []DisplayLine{line}
	}
	args := formatToolSummaryArgs(call.Input)
	return formatToolSummaryDisplay(call.Name, args, formatToolDescription(call.Input))
}

func formatCoordinationToolCall(call ToolCall) (DisplayLine, bool) {
	if !strings.EqualFold(strings.TrimSpace(call.Name), "Bash") {
		return DisplayLine{}, false
	}
	command, _ := call.Input["command"].(string)
	if command == "" {
		return DisplayLine{}, false
	}
	return formatAWCoordinationCommand(command)
}

func formatAWCoordinationCommand(command string) (DisplayLine, bool) {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) < 3 || fields[0] != "aw" {
		return DisplayLine{}, false
	}

	switch fields[1] {
	case "task":
		if len(fields) < 3 {
			return DisplayLine{}, false
		}
		action := strings.TrimSpace(fields[2])
		switch action {
		case "create":
			return DisplayLine{Kind: DisplayKindTaskActivity, Text: primaryBulletPrefix + "task create"}, true
		case "update", "close":
			ref := firstNonFlag(fields[3:])
			if ref == "" {
				return DisplayLine{}, false
			}
			return DisplayLine{Kind: DisplayKindTaskActivity, Text: fmt.Sprintf("%stask %s %s", primaryBulletPrefix, action, ref)}, true
		default:
			return DisplayLine{}, false
		}
	case "mail":
		if fields[2] != "send" {
			return DisplayLine{}, false
		}
		alias := findFlagValue(fields[3:], "--to")
		if alias == "" {
			return DisplayLine{}, false
		}
		return DisplayLine{Kind: DisplayKindCommunication, Text: FormatCommLabel("to", alias, "mail")}, true
	case "chat":
		switch fields[2] {
		case "send-and-wait", "send-and-leave":
			alias := firstNonFlag(fields[3:])
			if alias == "" {
				return DisplayLine{}, false
			}
			return DisplayLine{Kind: DisplayKindCommunication, Text: FormatCommLabel("to", alias, "chat")}, true
		default:
			return DisplayLine{}, false
		}
	default:
		return DisplayLine{}, false
	}
}

func FormatCommLabel(direction string, alias string, channel string) string {
	alias = strings.TrimSpace(alias)
	channel = strings.TrimSpace(channel)
	direction = strings.TrimSpace(direction)
	label := primaryDisplayBullet
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

func SplitDisplayText(kind DisplayKind, text string) []DisplayLine {
	text = strings.ReplaceAll(text, "\r", "")
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil
	}
	parts := strings.Split(text, "\n")
	lines := make([]DisplayLine, 0, len(parts))
	for _, part := range parts {
		lines = append(lines, DisplayLine{Kind: kind, Text: part})
	}
	return lines
}

func isIncomingCommDisplay(display string) bool {
	return strings.HasPrefix(strings.TrimSpace(display), primaryBulletPrefix+"from ")
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

func formatToolSummaryDisplay(name string, args []string, description string) []DisplayLine {
	prefix := "· "
	name = strings.TrimSpace(name)
	if name != "" && !strings.EqualFold(name, "Bash") {
		prefix += name + " "
	}
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, args...)
	if description != "" {
		parts = append(parts, "— "+description)
	}
	if len(parts) == 0 {
		return []DisplayLine{{Kind: DisplayKindTool, Text: strings.TrimRight(prefix, " ")}}
	}
	return []DisplayLine{{
		Kind: DisplayKindTool,
		Text: truncateText(prefix+strings.Join(parts, " "), 220),
	}}
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
