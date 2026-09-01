package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// Read-side verbs of the beads mail delegate, per docs/beads-mail-delegate.md
// §6, §7, §8. Everything goes through the Go client directly: `aw mail inbox`
// acknowledges what it presents, which is the wrong semantic for a gt-shaped
// surface, so inbox and peek here are read-only and `read` is what marks read.

// splitBeadsMailEnvelope parses the LAST fenced beads-mail block out of a
// body (§9). A malformed envelope is ordinary body text — inbound mail is
// data, never an error.
func splitBeadsMailEnvelope(body string) (string, *beadsMailEnvelope) {
	const marker = "```beads-mail\n"
	idx := strings.LastIndex(body, marker)
	if idx < 0 {
		return body, nil
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, "```")
	if end < 0 {
		return body, nil
	}
	var env beadsMailEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(rest[:end])), &env); err != nil || env.V < 1 {
		return body, nil
	}
	stripped := strings.TrimRight(body[:idx], "\n")
	if tail := strings.TrimSpace(rest[end+3:]); tail != "" {
		stripped = stripped + "\n" + tail
	}
	return stripped, &env
}

// beadsMailStatePath is the workspace-local index state for `read <index>`
// (§7): the message ids of the most recent inbox listing. Never committed.
// Selection.WorkspacePath is the workspace.yaml FILE, not a directory —
// derive the worktree root from it; standalone identities (no workspace
// binding) fall back to the working directory.
func beadsMailStatePath(sel *awconfig.Selection) string {
	root := ""
	if sel != nil && strings.TrimSpace(sel.WorkspacePath) != "" {
		root = awconfig.WorktreeRootFromWorkspacePath(strings.TrimSpace(sel.WorkspacePath))
	}
	if root == "" {
		root, _ = os.Getwd()
	}
	return filepath.Join(root, ".aw", "beads-mail", "state.json")
}

type beadsMailState struct {
	LastInbox []string `json:"last_inbox"`
}

func saveBeadsMailInboxState(sel *awconfig.Selection, messageIDs []string) {
	path := beadsMailStatePath(sel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	encoded, err := json.Marshal(beadsMailState{LastInbox: messageIDs})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, encoded, 0o600)
}

// resolveBeadsMailMessageRef turns a message reference — an id, or a 1-based
// index into the most recent inbox listing — into a message id.
func resolveBeadsMailMessageRef(sel *awconfig.Selection, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	index, err := strconv.Atoi(ref)
	if err != nil {
		return ref, nil
	}
	content, readErr := os.ReadFile(beadsMailStatePath(sel))
	if readErr != nil {
		return "", usageError("no inbox listing to index into; run 'bd mail inbox' first, then 'bd mail read %d'", index)
	}
	var state beadsMailState
	if err := json.Unmarshal(content, &state); err != nil || len(state.LastInbox) == 0 {
		return "", usageError("no inbox listing to index into; run 'bd mail inbox' first, then 'bd mail read %d'", index)
	}
	if index < 1 || index > len(state.LastInbox) {
		return "", usageError("index %d is out of range; the last inbox listing had %d message(s)", index, len(state.LastInbox))
	}
	return state.LastInbox[index-1], nil
}

// beadsMailSenderLabel shows the local rig name where the map knows the
// sender, always alongside the verifiable identity (§5: attribution is a
// feature — show it).
func beadsMailSenderLabel(m beadsMailAddressMap, msg *awid.InboxMessage) string {
	identity := strings.TrimSpace(msg.FromAddress)
	if identity == "" {
		identity = strings.TrimSpace(msg.FromDID)
	}
	if identity == "" {
		identity = strings.TrimSpace(msg.FromAlias)
	}
	for _, key := range []string{strings.TrimSpace(msg.FromAddress), strings.TrimSpace(msg.FromDID)} {
		if key == "" {
			continue
		}
		if local := beadsMailDisplayName(m, key); local != "" {
			return fmt.Sprintf("%s (%s)", local, sanitizeBeadsMailDisplay(identity))
		}
	}
	return sanitizeBeadsMailDisplay(identity)
}

func beadsMailReadClient(cmd *cobra.Command, ctx context.Context) (*aweb.Client, *awconfig.Selection, beadsMailAddressMap, error) {
	c, sel, err := resolveMailMessagingClientSelection()
	if err != nil {
		return nil, nil, beadsMailAddressMap{}, beadsMailClientError(err)
	}
	beadsMailIdentifyTransport(c)
	if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
		return nil, nil, beadsMailAddressMap{}, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, beadsMailAddressMap{}, err
	}
	addressMap, err := loadBeadsMailAddressMap(cwd)
	if err != nil {
		return nil, nil, beadsMailAddressMap{}, err
	}
	return c, sel, addressMap, nil
}

func beadsMailPrintMessage(m beadsMailAddressMap, msg *awid.InboxMessage) {
	body, env := splitBeadsMailEnvelope(msg.Body)
	fmt.Printf("From: %s\n", beadsMailSenderLabel(m, msg))
	fmt.Printf("Subject: %s\n", sanitizeBeadsMailDisplay(msg.Subject))
	fmt.Printf("Date: %s\n", msg.CreatedAt)
	priority := string(msg.Priority)
	if env != nil && env.Priority != nil {
		priority = fmt.Sprintf("%s (beads %d)", priority, *env.Priority)
	}
	fmt.Printf("Priority: %s\n", priority)
	if env != nil && env.Type != "" {
		fmt.Printf("Type: %s\n", sanitizeBeadsMailDisplay(env.Type))
	}
	if env != nil && env.Pinned {
		fmt.Println("Pinned: true")
	}
	fmt.Printf("Message-Id: %s\n", msg.MessageID)
	fmt.Printf("Thread: %s\n", msg.ConversationID)
	fmt.Printf("\n%s\n", sanitizeBeadsMailBody(body))
}

// sanitizeBeadsMailBody neutralizes terminal-driving control characters in an
// inbound body while keeping the text readable: newlines and tabs survive,
// everything else in C0 plus DEL (notably ESC, which drives ANSI/OSC escape
// sequences) becomes '?'. Senders are verified, not trusted.
func sanitizeBeadsMailBody(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

func beadsMailLogReceived(sel *awconfig.Selection, msg *awid.InboxMessage) {
	if msg.ReadAt != nil {
		return
	}
	from := preferredIdentityDisplayLabel(msg.FromAlias, msg.FromAddress, msg.FromStableID, msg.FromDID, "")
	to := preferredIdentityDisplayLabel(msg.ToAlias, msg.ToAddress, msg.ToStableID, msg.ToDID, "")
	appendCommLog(defaultLogsDir(), commLogNameForSelection(sel), &CommLogEntry{
		Timestamp:      msg.CreatedAt,
		Dir:            "recv",
		Channel:        "mail",
		MessageID:      msg.MessageID,
		ConversationID: msg.ConversationID,
		From:           from,
		To:             to,
		Subject:        msg.Subject,
		Body:           msg.Body,
	})
}

var (
	beadsMailInboxUnread bool
	beadsMailInboxAll    bool
	beadsMailInboxJSON   bool
	beadsMailInboxCursor string
)

var beadsMailInboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "List unread messages (read-only; reading is what marks read)",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return usageError("inbox for another identity is not supported: this workspace has one aweb identity")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, sel, addressMap, err := beadsMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		resp, err := c.Inbox(ctx, awid.InboxParams{
			UnreadOnly: !beadsMailInboxAll,
			Limit:      50,
			Cursor:     beadsMailInboxCursor,
		})
		if err != nil {
			return err
		}
		if beadsMailInboxJSON {
			printJSON(resp)
		} else if len(resp.Messages) == 0 {
			fmt.Println("No unread mail.")
		} else {
			for i, msg := range resp.Messages {
				state := " "
				if msg.ReadAt == nil {
					state = "*"
				}
				fmt.Printf("%2d %s %s — %s (%s)\n", i+1, state, beadsMailSenderLabel(addressMap, &msg), sanitizeBeadsMailDisplay(msg.Subject), msg.MessageID)
			}
			if resp.HasMore {
				fmt.Printf("More messages exist; continue with: bd mail inbox --cursor %s\n", resp.NextCursor)
			}
		}
		// No comm-log write here: inbox is read-only and meant for polling,
		// so the ReadAt dedup guard aw mail inbox relies on never trips.
		// The receipt is logged at read time, where the ack makes it sound.
		ids := make([]string, 0, len(resp.Messages))
		for i := range resp.Messages {
			ids = append(ids, resp.Messages[i].MessageID)
		}
		saveBeadsMailInboxState(sel, ids)
		return nil
	},
}

var beadsMailReadJSON bool

var beadsMailReadCmd = &cobra.Command{
	Use:     "read <message-id|index>",
	Aliases: []string{"show"},
	Short:   "Read a message and mark it read",
	Long: `Read one message by id, or by its number in the most recent inbox
listing. Reading marks the message read (unlike gt mail read, which does
not) because read state drives the wake path here; use peek or thread
for a look that changes nothing.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
			return usageError("usage: bd mail read <message-id|index>")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, sel, addressMap, err := beadsMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		messageID, err := resolveBeadsMailMessageRef(sel, args[0])
		if err != nil {
			return err
		}
		msg, err := beadsMailSourceMessage(ctx, c, messageID)
		if err != nil {
			return err
		}
		if beadsMailReadJSON {
			printJSON(msg)
		} else {
			beadsMailPrintMessage(addressMap, msg)
		}
		beadsMailLogReceived(sel, msg)
		if msg.ReadAt == nil {
			if _, ackErr := c.AckMessage(ctx, messageID); ackErr != nil {
				return fmt.Errorf("message displayed, but it could not be marked read: %w", ackErr)
			}
		}
		return nil
	},
}

var beadsMailPeekCmd = &cobra.Command{
	Use:   "peek",
	Short: "Preview the first unread message without marking it read",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, _, addressMap, err := beadsMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		resp, err := c.Inbox(ctx, awid.InboxParams{UnreadOnly: true, Limit: 1})
		if err != nil {
			return err
		}
		if len(resp.Messages) == 0 {
			fmt.Println("No unread mail.")
			return nil
		}
		beadsMailPrintMessage(addressMap, &resp.Messages[0])
		return nil
	},
}

var beadsMailThreadJSON bool

var beadsMailThreadCmd = &cobra.Command{
	Use:   "thread <thread-id>",
	Short: "View a message thread (oldest first)",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
			return usageError("usage: bd mail thread <thread-id>")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		const threadLimit = 500
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, _, addressMap, err := beadsMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		resp, err := c.MailConversation(ctx, strings.TrimSpace(args[0]), threadLimit)
		if err != nil {
			return err
		}
		if beadsMailThreadJSON {
			printJSON(resp)
			return nil
		}
		for i := range resp.Messages {
			msg := &resp.Messages[i]
			if i > 0 {
				fmt.Println("---")
			}
			beadsMailPrintMessage(addressMap, msg)
		}
		if len(resp.Messages) == threadLimit {
			fmt.Printf("Showing the oldest %d messages; the thread may be longer than this window.\n", threadLimit)
		}
		return nil
	},
}

var beadsMailMarkReadAll bool

var beadsMailMarkReadCmd = &cobra.Command{
	Use:     "mark-read [message-id|index...]",
	Aliases: []string{"ack"},
	Short:   "Mark messages as read",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && !beadsMailMarkReadAll {
			return usageError("give message ids (or inbox indexes), or --all")
		}
		if len(args) > 0 && beadsMailMarkReadAll {
			return usageError("give message ids or --all, not both")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, sel, _, err := beadsMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		var ids []string
		capped := false
		if beadsMailMarkReadAll {
			cursor := ""
			for page := 0; ; page++ {
				if page >= 20 {
					capped = true
					break
				}
				resp, err := c.Inbox(ctx, awid.InboxParams{UnreadOnly: true, Limit: 200, Cursor: cursor})
				if err != nil {
					return err
				}
				for _, msg := range resp.Messages {
					ids = append(ids, msg.MessageID)
				}
				if !resp.HasMore || resp.NextCursor == "" {
					break
				}
				cursor = resp.NextCursor
			}
		} else {
			for _, arg := range args {
				id, err := resolveBeadsMailMessageRef(sel, arg)
				if err != nil {
					return err
				}
				ids = append(ids, id)
			}
		}
		acked := 0
		failed := 0
		for _, id := range ids {
			if _, err := c.AckMessage(ctx, id); err != nil {
				debugLog("ack beads mail %s: %v", id, err)
				failed++
				continue
			}
			acked++
		}
		fmt.Printf("marked %d message(s) read\n", acked)
		if capped {
			fmt.Println("More unread mail remains beyond this pass; run 'bd mail mark-read --all' again.")
		}
		if failed > 0 {
			return fmt.Errorf("failed to mark %d message(s) read; they remain unread", failed)
		}
		return nil
	},
}

func init() {
	beadsMailInboxCmd.Flags().BoolVarP(&beadsMailInboxUnread, "unread", "u", false, "Show only unread messages (the default)")
	beadsMailInboxCmd.Flags().BoolVarP(&beadsMailInboxAll, "all", "a", false, "Show all messages, read and unread (gt's default view)")
	beadsMailInboxCmd.Flags().BoolVar(&beadsMailInboxJSON, "json", false, "Output as JSON")
	beadsMailInboxCmd.Flags().StringVar(&beadsMailInboxCursor, "cursor", "", "Continue a previous listing from its printed cursor")
	beadsMailInboxCmd.MarkFlagsMutuallyExclusive("unread", "all")
	beadsMailReadCmd.Flags().BoolVar(&beadsMailReadJSON, "json", false, "Output as JSON (raw message, envelope included)")
	beadsMailThreadCmd.Flags().BoolVar(&beadsMailThreadJSON, "json", false, "Output as JSON")
	beadsMailMarkReadCmd.Flags().BoolVar(&beadsMailMarkReadAll, "all", false, "Mark all unread messages as read")
}
