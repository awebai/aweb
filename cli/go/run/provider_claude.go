package run

import (
	"encoding/json"
	"fmt"
	"strings"
)

func (ClaudeProvider) Name() string {
	return "claude"
}

func (ClaudeProvider) BuildCommand(prompt string, opts BuildOptions) ([]string, error) {
	if strings.TrimSpace(prompt) == "" {
		return nil, fmt.Errorf("prompt cannot be empty")
	}

	command := []string{
		"claude",
		"-p",
		prompt,
		"--dangerously-skip-permissions",
		"--output-format",
		"stream-json",
		"--verbose",
		"--include-partial-messages",
	}

	if opts.ContinueSession {
		command = append(command, "--continue")
	} else if strings.TrimSpace(opts.SessionID) != "" {
		command = append(command, "--resume", opts.SessionID)
	}
	if strings.TrimSpace(opts.AllowedTools) != "" {
		command = append(command, "--allowedTools", opts.AllowedTools)
	}
	if strings.TrimSpace(opts.Model) != "" {
		command = append(command, "--model", opts.Model)
	}
	for _, dir := range opts.AddDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		command = append(command, "--add-dir", dir)
	}
	command = append(command, opts.ProviderArgs...)

	return command, nil
}

func (ClaudeProvider) BuildResumeCommand(opts BuildOptions) ([]string, error) {
	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		return nil, fmt.Errorf("session id is required")
	}

	command := []string{"claude", "--resume", sessionID}
	if strings.TrimSpace(opts.Model) != "" {
		command = append(command, "--model", opts.Model)
	}
	for _, dir := range opts.AddDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		command = append(command, "--add-dir", dir)
	}
	command = append(command, opts.ProviderArgs...)
	return command, nil
}

func (ClaudeProvider) ParseOutput(line string) (*Event, error) {
	var envelope ClaudeEnvelope
	if err := json.Unmarshal([]byte(line), &envelope); err != nil {
		return nil, err
	}

	switch envelope.Type {
	case "stream_event":
		if envelope.Event.Delta.Type == "text_delta" {
			return &Event{Type: EventText, Text: envelope.Event.Delta.Text}, nil
		}
	case "assistant":
		var message struct {
			Content []struct {
				Type  string         `json:"type"`
				Name  string         `json:"name"`
				Input map[string]any `json:"input"`
			} `json:"content"`
			Usage struct {
				InputTokens              int `json:"input_tokens"`
				CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int `json:"cache_read_input_tokens"`
				OutputTokens             int `json:"output_tokens"`
			} `json:"usage"`
			Model string `json:"model"`
		}
		if err := json.Unmarshal(envelope.Message, &message); err != nil {
			return nil, err
		}
		calls := make([]ToolCall, 0, len(message.Content))
		for _, block := range message.Content {
			if block.Type != "tool_use" {
				continue
			}
			calls = append(calls, ToolCall{Name: block.Name, Input: block.Input})
		}
		var usage *UsageStats
		if message.Usage.InputTokens > 0 || message.Usage.CacheCreationInputTokens > 0 || message.Usage.CacheReadInputTokens > 0 || message.Usage.OutputTokens > 0 {
			usage = &UsageStats{
				InputTokens:              message.Usage.InputTokens,
				CacheCreationInputTokens: message.Usage.CacheCreationInputTokens,
				CacheReadInputTokens:     message.Usage.CacheReadInputTokens,
				OutputTokens:             message.Usage.OutputTokens,
			}
		}
		if len(calls) > 0 {
			return &Event{Type: EventToolCall, ToolCalls: calls, Usage: usage}, nil
		}
		if usage != nil {
			return &Event{Usage: usage}, nil
		}
	case "tool_result":
		return &Event{Type: EventToolResult, Text: claudeToolResultText(envelope.Content)}, nil
	case "result":
		duration := envelope.DurationMS
		if duration == 0 {
			duration = envelope.Stats.DurationMS
		}
		costUSD := envelope.CostUSD
		if costUSD == nil {
			costUSD = envelope.TotalCostUSD
		}
		return &Event{
			Type:       EventDone,
			Text:       strings.TrimSpace(envelope.Result),
			DurationMS: duration,
			CostUSD:    costUSD,
			Session:    envelope.Session,
			IsError:    envelope.IsError,
		}, nil
	case "system":
		text, err := claudeSystemEventText(envelope)
		if err != nil {
			return nil, err
		}
		return &Event{
			Type:    EventSystem,
			Text:    text,
			Session: claudeSystemSessionID(envelope),
		}, nil
	}

	return &Event{}, nil
}

func (ClaudeProvider) SessionID(event *Event) string {
	if event == nil {
		return ""
	}
	return event.Session
}

func claudeToolResultText(content any) string {
	switch typed := content.(type) {
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			blockType, _ := block["type"].(string)
			if blockType != "text" {
				continue
			}
			text, _ := block["text"].(string)
			if strings.TrimSpace(text) != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprintf("%v", content)
	}
}

func claudeSystemMessageText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, nil
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err == nil {
		parts := make([]string, 0, 3)
		if sessionID, _ := payload["session_id"].(string); strings.TrimSpace(sessionID) != "" {
			parts = append(parts, fmt.Sprintf("session %s", truncateText(sessionID, 12)))
		}
		if cwd, _ := payload["cwd"].(string); strings.TrimSpace(cwd) != "" {
			parts = append(parts, fmt.Sprintf("cwd=%s", truncateText(cwd, 40)))
		}
		if model, _ := payload["model"].(string); strings.TrimSpace(model) != "" {
			parts = append(parts, fmt.Sprintf("model=%s", model))
		}
		if len(parts) == 0 {
			return "session event", nil
		}
		return strings.Join(parts, "  "), nil
	}

	return "", nil
}

func claudeSystemEventText(envelope ClaudeEnvelope) (string, error) {
	if len(envelope.Message) > 0 && string(envelope.Message) != "null" {
		text, err := claudeSystemMessageText(envelope.Message)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(text) != "" {
			return text, nil
		}
	}

	parts := make([]string, 0, 4)
	if subtype := strings.TrimSpace(envelope.Subtype); subtype != "" && subtype != "init" {
		parts = append(parts, subtype)
	}
	if sessionID := strings.TrimSpace(envelope.Session); sessionID != "" {
		parts = append(parts, fmt.Sprintf("session %s", truncateText(sessionID, 12)))
	}
	if cwd := strings.TrimSpace(envelope.CWD); cwd != "" {
		parts = append(parts, fmt.Sprintf("cwd=%s", truncateText(cwd, 40)))
	}
	if model := strings.TrimSpace(envelope.Model); model != "" {
		parts = append(parts, fmt.Sprintf("model=%s", model))
	}
	if len(parts) == 0 {
		if subtype := strings.TrimSpace(envelope.Subtype); subtype != "" {
			return subtype, nil
		}
		return "", nil
	}

	return strings.Join(parts, "  "), nil
}

func claudeSystemSessionID(envelope ClaudeEnvelope) string {
	if len(envelope.Message) > 0 && string(envelope.Message) != "null" {
		var payload map[string]any
		if err := json.Unmarshal(envelope.Message, &payload); err == nil {
			if sessionID, _ := payload["session_id"].(string); strings.TrimSpace(sessionID) != "" {
				return strings.TrimSpace(sessionID)
			}
		}
	}
	return strings.TrimSpace(envelope.Session)
}
