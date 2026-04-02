package run

import (
	"strings"

	awid "github.com/awebai/aw/awid"
)

func ParseControlSubmission(text string) ControlEvent {
	text = strings.TrimSpace(text)
	switch text {
	case "/quit", "/exit":
		return ControlEvent{Type: ControlQuit}
	case "/stop":
		return ControlEvent{Type: ControlStop}
	case "/wait":
		return ControlEvent{Type: ControlWait}
	case "/autofeed on":
		return ControlEvent{Type: ControlAutofeedOn}
	case "/autofeed off":
		return ControlEvent{Type: ControlAutofeedOff}
	case "/help":
		return ControlEvent{Type: ControlHelp}
	default:
		if strings.HasPrefix(text, "/provider") {
			return ControlEvent{
				Type: ControlProviderInput,
				Text: strings.TrimSpace(strings.TrimPrefix(text, "/provider")),
			}
		}
		if strings.HasPrefix(text, "/") {
			return ControlEvent{Type: ControlUnknownCommand, Text: text}
		}
		return ControlEvent{Type: ControlPrompt, Text: text}
	}
}

func FormatInputLine(promptLabel string, value string) string {
	if strings.TrimSpace(promptLabel) == "" {
		promptLabel = DefaultInputPromptLabel
	}
	if value == "" {
		return promptLabel
	}
	return promptLabel + value
}

func InputValueFromLine(line string, promptLabel string) string {
	line = strings.TrimLeft(line, " \t")
	if strings.TrimSpace(promptLabel) == "" {
		promptLabel = DefaultInputPromptLabel
	}
	trimmedPrompt := strings.TrimSpace(promptLabel)
	if line == "" || line == trimmedPrompt {
		return ""
	}
	if strings.HasPrefix(line, promptLabel) {
		return strings.TrimPrefix(line, promptLabel)
	}
	if strings.HasPrefix(line, trimmedPrompt) {
		return strings.TrimPrefix(line, trimmedPrompt)
	}
	return line
}

func ControlEventFromAgentEvent(evt awid.AgentEvent) (ControlEvent, bool) {
	switch evt.Type {
	case awid.AgentEventControlPause:
		return ControlEvent{Type: ControlWait}, true
	case awid.AgentEventControlResume:
		return ControlEvent{Type: ControlResume}, true
	case awid.AgentEventControlInterrupt:
		return ControlEvent{Type: ControlStop}, true
	case awid.AgentEventError:
		return ControlEvent{Type: ControlStreamError, Text: strings.TrimSpace(evt.Text)}, true
	default:
		return ControlEvent{}, false
	}
}
