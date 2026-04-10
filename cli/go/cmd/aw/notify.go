package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/chat"
	"github.com/spf13/cobra"
)

const notifyCooldown = 10 * time.Second

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Check for pending chat notifications for Claude Code hooks",
	Long: `Check for pending chat notifications.

Silent if no pending chats; outputs JSON with additionalContext if there are
messages waiting. Designed for Claude Code PostToolUse hooks so notifications
are surfaced to the agent automatically.

Hook configuration in .claude/settings.json (set up via aw init --setup-hooks):
  "hooks": {
    "PostToolUse": [{
      "matcher": ".*",
      "hooks": [{"type": "command", "command": "aw notify"}]
    }]
  }`,
	Args: cobra.NoArgs,
	RunE: runNotify,
}

func init() {
	rootCmd.AddCommand(notifyCmd)
}

func runNotify(cmd *cobra.Command, args []string) error {
	c, sel, err := resolveClientSelection()
	if err != nil || c == nil || sel == nil {
		return nil
	}

	configPath, err := awconfig.DefaultUserStateDir()
	if err != nil {
		configPath = ""
	}
	stampPath := notifyStampPath(sel.Alias, configPath)
	if notifyCooldownActive(stampPath, notifyCooldown) {
		return nil
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
	defer cancel()

	result, err := chat.Pending(ctx, c.Client)
	touchNotifyStamp(stampPath)
	if err != nil || result == nil || len(result.Pending) == 0 {
		return nil
	}

	output := formatNotifyOutput(result, sel.Alias)
	if output == "" {
		return nil
	}
	fmt.Print(formatHookOutput(output))
	return nil
}

// notifyStampPath returns the cooldown stamp file path for an identity within a
// specific CLI config scope. This keeps notify cooldown state local to the
// active aw configuration instead of leaking across unrelated worktrees/tests
// that happen to use the same identity handle.
func notifyStampPath(identity, configPath string) string {
	h := sha256.Sum256([]byte(identity + "\n" + configPath))
	return filepath.Join(os.TempDir(), "aw-notify-"+hex.EncodeToString(h[:8]))
}

// notifyCooldownActive returns true if the stamp file was modified within the cooldown period.
func notifyCooldownActive(stampPath string, cooldown time.Duration) bool {
	info, err := os.Stat(stampPath)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < cooldown
}

// touchNotifyStamp creates or updates the stamp file's modification time.
func touchNotifyStamp(stampPath string) {
	f, err := os.Create(stampPath)
	if err != nil {
		return
	}
	f.Close()
}

func formatNotifyOutput(result *chat.PendingResult, selfAlias string) string {
	if result == nil || len(result.Pending) == 0 {
		return ""
	}

	var urgent []string
	var regular []string
	for _, pending := range result.Pending {
		from := preferredIdentityLabel(
			strings.TrimSpace(pending.LastFrom),
			strings.TrimSpace(pending.LastFromAddress),
			"",
		)
		if from == "" {
			for idx, participant := range pending.Participants {
				participant = preferredIdentityLabel(
					strings.TrimSpace(participant),
					func() string {
						if idx < len(pending.ParticipantAddresses) {
							return strings.TrimSpace(pending.ParticipantAddresses[idx])
						}
						return ""
					}(),
					"",
				)
				if participant == "" || notifyIdentityMatchesSelf(participant, selfAlias) {
					continue
				}
				from = participant
				break
			}
		}
		if notifyIdentityMatchesSelf(from, selfAlias) {
			continue
		}
		if from == "" {
			continue
		}
		if pending.SenderWaiting {
			urgent = append(urgent, from)
		} else {
			regular = append(regular, from)
		}
	}

	if len(urgent) == 0 && len(regular) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║         📬 AGENT: YOU HAVE PENDING CHAT MESSAGES             ║\n")
	sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	for _, from := range urgent {
		sb.WriteString(padNotifyLine(fmt.Sprintf("║ ⚠️  URGENT: %s is WAITING for your reply", from)))
	}
	for _, from := range regular {
		sb.WriteString(padNotifyLine(fmt.Sprintf("║ 💬 Unread message from %s", from)))
	}
	sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	sb.WriteString("║ YOU MUST RUN: aw chat pending                                ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n")
	sb.WriteString("\n")
	return sb.String()
}

func notifyIdentityMatchesSelf(value string, selfAlias string) bool {
	value = strings.TrimSpace(value)
	selfAlias = strings.TrimSpace(selfAlias)
	if value == "" || selfAlias == "" {
		return false
	}
	if strings.EqualFold(value, selfAlias) {
		return true
	}
	return strings.EqualFold(handleFromAddress(value), selfAlias)
}

func padNotifyLine(line string) string {
	const width = 65
	runeCount := utf8.RuneCountInString(line)
	if runeCount >= width {
		// Truncate by runes, not bytes
		runes := []rune(line)
		return string(runes[:width]) + "║\n"
	}
	return line + strings.Repeat(" ", width-runeCount) + "║\n"
}

func formatHookOutput(content string) string {
	output := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PostToolUse",
			"additionalContext": content,
		},
	}
	data, _ := json.Marshal(output)
	return string(data)
}
