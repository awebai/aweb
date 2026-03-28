package run

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type CodexProvider struct{}

type codexEnvelope struct {
	Type     string          `json:"type"`
	ThreadID string          `json:"thread_id"`
	Item     json.RawMessage `json:"item"`
}

type codexItem struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	Text             string `json:"text"`
	Command          string `json:"command"`
	AggregatedOutput string `json:"aggregated_output"`
	ExitCode         *int   `json:"exit_code"`
	Status           string `json:"status"`
}

func (CodexProvider) Name() string {
	return "codex"
}

func (CodexProvider) BuildCommand(prompt string, opts BuildOptions) ([]string, error) {
	if strings.TrimSpace(prompt) == "" {
		return nil, fmt.Errorf("prompt cannot be empty")
	}
	if strings.TrimSpace(opts.AllowedTools) != "" {
		return nil, fmt.Errorf("provider codex does not support --allowed-tools")
	}

	command := []string{"codex", "exec", "--skip-git-repo-check"}
	if !opts.TripOnDanger {
		command = append(command, "--dangerously-bypass-approvals-and-sandbox")
	}
	isResume := strings.TrimSpace(opts.SessionID) != "" || opts.ContinueSession
	if !isResume {
		for _, dir := range opts.AddDirs {
			if strings.TrimSpace(dir) == "" {
				continue
			}
			command = append(command, "--add-dir", dir)
		}
	}
	if strings.TrimSpace(opts.SessionID) != "" {
		command = append(command, "resume", opts.SessionID)
	} else if opts.ContinueSession {
		command = append(command, "resume", "--last")
	}
	command = append(command, "--json")
	if strings.TrimSpace(opts.Model) != "" {
		command = append(command, "-m", opts.Model)
	}
	for _, path := range opts.ImagePaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		command = append(command, "--image", path)
	}
	command = append(command, opts.ProviderArgs...)
	if opts.PromptTransport == PromptTransportStdin {
		command = append(command, "-")
	} else {
		command = append(command, prompt)
	}
	return command, nil
}

func (CodexProvider) BuildResumeCommand(opts BuildOptions) ([]string, error) {
	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		return nil, fmt.Errorf("session id is required")
	}

	command := []string{"codex", "exec", "resume", "--skip-git-repo-check"}
	if !opts.TripOnDanger {
		command = append(command, "--dangerously-bypass-approvals-and-sandbox")
	}
	if strings.TrimSpace(opts.Model) != "" {
		command = append(command, "-m", opts.Model)
	}
	command = append(command, opts.ProviderArgs...)
	command = append(command, sessionID)
	return command, nil
}

func (CodexProvider) ParseOutput(line string) (*Event, error) {
	var envelope codexEnvelope
	if err := json.Unmarshal([]byte(line), &envelope); err != nil {
		return nil, err
	}

	switch envelope.Type {
	case "thread.started":
		session := strings.TrimSpace(envelope.ThreadID)
		if session == "" {
			return &Event{}, nil
		}
		return &Event{
			Type:    EventSystem,
			Text:    fmt.Sprintf("session %s", truncateText(session, 12)),
			Session: session,
		}, nil
	case "item.started":
		item, err := codexParseItem(envelope.Item)
		if err != nil {
			return nil, err
		}
		if item.Type == "command_execution" {
			return &Event{
				Type: EventToolCall,
				ToolCalls: []ToolCall{{
					Name: "Bash",
					Input: map[string]any{
						"command": codexDisplayCommand(item.Command),
					},
				}},
			}, nil
		}
	case "item.completed":
		item, err := codexParseItem(envelope.Item)
		if err != nil {
			return nil, err
		}
		switch item.Type {
		case "agent_message":
			return &Event{Type: EventText, Text: item.Text}, nil
		case "command_execution":
			return &Event{Type: EventToolResult, Text: codexToolResultText(item)}, nil
		}
	case "turn.completed":
		return &Event{Type: EventDone}, nil
	}

	return &Event{}, nil
}

func (CodexProvider) SessionID(event *Event) string {
	if event == nil {
		return ""
	}
	return event.Session
}

func codexParseItem(raw json.RawMessage) (codexItem, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return codexItem{}, nil
	}
	var item codexItem
	if err := json.Unmarshal(raw, &item); err != nil {
		return codexItem{}, err
	}
	return item, nil
}

func codexDisplayCommand(command string) string {
	command = strings.TrimSpace(command)
	for _, prefix := range []string{
		"/bin/zsh -lc ",
		"/bin/bash -lc ",
		"zsh -lc ",
		"bash -lc ",
		"sh -lc ",
	} {
		if !strings.HasPrefix(command, prefix) {
			continue
		}
		remainder := strings.TrimSpace(strings.TrimPrefix(command, prefix))
		if unquoted, err := strconv.Unquote(remainder); err == nil {
			return unquoted
		}
		if len(remainder) >= 2 {
			if remainder[0] == '\'' && remainder[len(remainder)-1] == '\'' {
				return remainder[1 : len(remainder)-1]
			}
			if remainder[0] == '"' && remainder[len(remainder)-1] == '"' {
				return remainder[1 : len(remainder)-1]
			}
		}
		return remainder
	}
	return command
}

func codexToolResultText(item codexItem) string {
	text := strings.TrimSpace(item.AggregatedOutput)
	if text != "" {
		if item.ExitCode != nil && *item.ExitCode != 0 {
			return fmt.Sprintf("%s (exit %d)", text, *item.ExitCode)
		}
		return text
	}
	if item.ExitCode != nil && *item.ExitCode != 0 {
		return fmt.Sprintf("exit %d", *item.ExitCode)
	}
	return ""
}
