package main

import (
	"context"
	"fmt"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	awrun "github.com/awebai/aw/run"
)

type runWakeResolution struct {
	Skip         bool
	CycleContext string
}

type runWakeResolver func(context.Context, awid.AgentEvent) (runWakeResolution, error)

type runDispatcher struct {
	workPromptSuffix  string
	commsPromptSuffix string
	resolveWake       runWakeResolver
}

func newRunDispatcher(settings awrun.Settings, resolveWake runWakeResolver) awrun.Dispatcher {
	return runDispatcher{
		workPromptSuffix:  strings.TrimSpace(settings.WorkPromptSuffix),
		commsPromptSuffix: strings.TrimSpace(settings.CommsPromptSuffix),
		resolveWake:       resolveWake,
	}
}

func (d runDispatcher) Next(ctx context.Context, autofeed bool, wakeEvent *awid.AgentEvent) (awrun.DispatchDecision, error) {
	if wakeEvent == nil {
		return awrun.DispatchDecision{Skip: true}, nil
	}

	switch wakeEvent.Type {
	case awid.AgentEventMailMessage, awid.AgentEventChatMessage, awid.AgentEventActionableMail, awid.AgentEventActionableChat:
		resolved := runWakeResolution{
			CycleContext: formatFallbackCommsContext(*wakeEvent),
		}
		if d.resolveWake != nil {
			var err error
			resolved, err = d.resolveWake(ctx, *wakeEvent)
			if err != nil {
				return awrun.DispatchDecision{}, err
			}
		}
		if resolved.Skip {
			return awrun.DispatchDecision{Skip: true, WaitSeconds: awrun.DefaultWaitSeconds}, nil
		}
		return awrun.DispatchDecision{
			CycleContext: joinPromptSections(resolved.CycleContext, d.commsPromptSuffix),
			WaitSeconds:  awrun.DefaultWaitSeconds,
		}, nil
	case awid.AgentEventWorkAvailable, awid.AgentEventClaimUpdate, awid.AgentEventClaimRemoved:
		if !autofeed {
			return awrun.DispatchDecision{Skip: true}, nil
		}
		return awrun.DispatchDecision{
			CycleContext: joinPromptSections(formatWorkWakePrompt(*wakeEvent), d.workPromptSuffix),
			WaitSeconds:  awrun.DefaultWaitSeconds,
		}, nil
	default:
		return awrun.DispatchDecision{Skip: true}, nil
	}
}

func newRunWakeValidator(client *aweb.Client) runWakeResolver {
	if client == nil || client.Client == nil {
		return nil
	}
	return func(ctx context.Context, evt awid.AgentEvent) (runWakeResolution, error) {
		switch evt.Type {
		case awid.AgentEventChatMessage, awid.AgentEventActionableChat:
			return resolveChatWake(ctx, client, evt)
		case awid.AgentEventMailMessage, awid.AgentEventActionableMail:
			return resolveMailWake(ctx, client, evt)
		case awid.AgentEventWorkAvailable, awid.AgentEventClaimUpdate, awid.AgentEventClaimRemoved:
			return runWakeResolution{CycleContext: formatWorkWakePrompt(evt)}, nil
		default:
			return runWakeResolution{}, nil
		}
	}
}

func resolveChatWake(ctx context.Context, client *aweb.Client, evt awid.AgentEvent) (runWakeResolution, error) {
	sessionID := strings.TrimSpace(evt.SessionID)
	if sessionID == "" {
		return runWakeResolution{CycleContext: formatFallbackCommsContext(evt)}, nil
	}
	resp, err := client.ChatPending(ctx)
	if err != nil {
		return runWakeResolution{}, fmt.Errorf("check pending chat for wake %s: %w", sessionID, err)
	}
	for _, pending := range resp.Pending {
		if strings.TrimSpace(pending.SessionID) != sessionID {
			continue
		}
		alias := strings.TrimSpace(evt.FromAlias)
		if alias == "" {
			alias = strings.TrimSpace(pending.LastFrom)
		}
		return runWakeResolution{
			CycleContext: formatIncomingChatContext(alias, pending.LastMessage),
		}, nil
	}
	return runWakeResolution{Skip: true}, nil
}

func resolveMailWake(ctx context.Context, client *aweb.Client, evt awid.AgentEvent) (runWakeResolution, error) {
	messageID := strings.TrimSpace(evt.MessageID)
	resp, err := client.Inbox(ctx, awid.InboxParams{UnreadOnly: true})
	if err != nil {
		return runWakeResolution{}, fmt.Errorf("check unread mail for wake %s: %w", messageID, err)
	}
	for _, msg := range resp.Messages {
		if messageID != "" && strings.TrimSpace(msg.MessageID) != messageID {
			continue
		}
		alias := strings.TrimSpace(msg.FromAlias)
		if alias == "" {
			alias = strings.TrimSpace(evt.FromAlias)
		}
		return runWakeResolution{
			CycleContext: formatIncomingMailContext(alias, msg.Subject, msg.Body),
		}, nil
	}
	if messageID == "" {
		return runWakeResolution{CycleContext: formatFallbackCommsContext(evt)}, nil
	}
	return runWakeResolution{Skip: true}, nil
}

func joinPromptSections(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, "\n\n")
}

func formatFallbackCommsContext(evt awid.AgentEvent) string {
	switch evt.Type {
	case awid.AgentEventActionableChat, awid.AgentEventChatMessage:
		return formatIncomingChatContext(evt.FromAlias, "")
	case awid.AgentEventActionableMail, awid.AgentEventMailMessage:
		return formatIncomingMailContext(evt.FromAlias, evt.Subject, "")
	default:
		return ""
	}
}

func formatIncomingChatContext(fromAlias string, body string) string {
	alias := formatWakeAlias(fromAlias)
	body = strings.TrimSpace(body)
	if body == "" {
		return fmt.Sprintf("<- %s (chat)", alias)
	}
	return formatIncomingCommBlock("<- "+alias+" (chat)", "", body)
}

func formatIncomingMailContext(fromAlias string, subject string, body string) string {
	alias := formatWakeAlias(fromAlias)
	subject = strings.TrimSpace(subject)
	body = strings.TrimSpace(body)
	switch {
	case subject != "" && body != "":
		return formatIncomingMailBlock("<- "+alias+" (mail)", subject, body)
	case subject != "":
		return fmt.Sprintf("<- %s (mail): %s", alias, subject)
	case body != "":
		return formatIncomingCommBlock("<- "+alias+" (mail)", "", body)
	default:
		return fmt.Sprintf("<- %s (mail)", alias)
	}
}

func formatIncomingCommBlock(head string, subject string, body string) string {
	lines := commBodyLines(body)
	if len(lines) == 0 {
		if subject == "" {
			return head
		}
		return fmt.Sprintf("%s: %s", head, subject)
	}

	first := lines[0]
	if subject != "" {
		first = subject + " — " + first
	}

	formatted := []string{fmt.Sprintf("%s: %s", head, first)}
	for _, line := range lines[1:] {
		formatted = append(formatted, "   "+line)
	}
	return strings.Join(formatted, "\n")
}

func formatIncomingMailBlock(head string, subject string, body string) string {
	formatted := []string{fmt.Sprintf("%s: %s", head, subject)}
	for _, line := range commBodyLines(body) {
		formatted = append(formatted, "   "+line)
	}
	return strings.Join(formatted, "\n")
}

func commBodyLines(body string) []string {
	body = strings.ReplaceAll(strings.TrimSpace(body), "\r", "")
	if body == "" {
		return nil
	}
	lines := strings.Split(body, "\n")
	formatted := make([]string, 0, len(lines))
	for _, line := range lines {
		formatted = append(formatted, strings.TrimRight(line, " "))
	}
	return formatted
}

func formatWorkWakePrompt(evt awid.AgentEvent) string {
	switch evt.Type {
	case awid.AgentEventWorkAvailable:
		return fmt.Sprintf(
			"Wake reason: work is available%s. Check ready work, claim the most appropriate task if needed, and continue the task-oriented cycle.",
			formatWakeTask(evt),
		)
	case awid.AgentEventClaimUpdate:
		status := ""
		if value := strings.TrimSpace(evt.Status); value != "" {
			status = fmt.Sprintf(" Status: %s.", value)
		}
		return fmt.Sprintf(
			"Wake reason: a claim changed%s.%s Review the updated claim state and adjust coordination before continuing.",
			formatWakeTask(evt),
			status,
		)
	case awid.AgentEventClaimRemoved:
		return fmt.Sprintf(
			"Wake reason: a claim was removed%s. Re-check ready work and coordination state before continuing.",
			formatWakeTask(evt),
		)
	default:
		return ""
	}
}

func formatWakeAlias(alias string) string {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return "another agent"
	}
	return alias
}

func formatWakeTask(evt awid.AgentEvent) string {
	title := strings.TrimSpace(evt.Title)
	taskID := strings.TrimSpace(evt.TaskID)
	switch {
	case title != "" && taskID != "":
		return fmt.Sprintf(": %s (%s)", title, taskID)
	case title != "":
		return fmt.Sprintf(": %s", title)
	case taskID != "":
		return fmt.Sprintf(" (%s)", taskID)
	default:
		return ""
	}
}
