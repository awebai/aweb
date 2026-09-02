package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The Gas City exec mail operations, per docs/gascity-mail-provider.md §6.
// Every one of them is invoked as its own process by gc, so each opens its own
// client; there is no session to keep.

// gcMailEnsureRunningCmd answers gc's once-per-provider readiness
// call. gc DISCARDS both the result and the error (exec.go: `_, _ =
// p.run(nil, "ensure-running")`), so this deliberately does no preflight: a
// check whose failure nobody can see is worse than no check, because it costs
// a round trip and teaches the operator nothing. Identity and reachability
// failures surface on the first real operation, where gc shows our stderr.
var gcMailEnsureRunningCmd = gcMailOp(
	"ensure-running",
	"Readiness probe (no-op: gc discards this operation's result)",
	`gc calls this once, before the first operation of a provider instance, and
throws away both its output and its exit status. There is nothing useful
to report through a channel nobody reads, so this succeeds immediately.
Run 'aw doctor' or 'aw gc-mail inbox' to check the setup for real.`,
	cobra.ArbitraryArgs,
	func(cmd *cobra.Command, args []string) error { return nil },
)

// gcMailSendCmd implements `send <to>` with {"from","subject","body"} on
// stdin. The sender is this workspace's cryptographic identity; the "from"
// gc supplies is its own local mailbox name and cannot change who the message
// is signed as (design record §5).
var gcMailSendCmd = gcMailOp(
	"send <to>",
	"Send a message (JSON on stdin, JSON message on stdout)",
	`Reads {"from":...,"subject":...,"body":...} on stdin and sends the body to
<to> under this workspace's verified aweb identity. The "from" field is
gc's local mailbox name; it is recorded nowhere as sender identity,
because sender identity here is cryptographic rather than asserted.

The message returned on stdout carries the RESOLVED aweb address in its
"to" field, which is how 'gc mail send --json' and 'gc mail read' disclose
where a mapped name actually delivered.`,
	gcMailExactArgs(1, "aw gc-mail send <to> < input.json"),
	func(cmd *cobra.Command, args []string) error {
		input, err := gcMailReadInput(cmd.InOrStdin())
		if err != nil {
			return err
		}
		addressMap, err := gcMailAddressMap()
		if err != nil {
			return err
		}
		target, err := resolveGCMailRecipient(addressMap, args[0])
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		var c *aweb.Client
		var sel *awconfig.Selection
		if target.Kind == "alias" {
			c, sel, err = resolveClientSelectionForAliasTarget(ctx, target.Value)
		} else {
			c, sel, err = resolveMailMessagingClientSelection()
		}
		if err != nil {
			return gcMailClientError(err)
		}
		gcMailIdentifyTransport(c)

		subject := gcMailSubject(input.Subject, input.Body)
		req := &awid.SendMessageRequest{
			Subject:  subject,
			Body:     input.Body,
			Priority: awid.PriorityNormal,
		}
		applyMailRecipientTarget(req, target.Kind, target.Value)

		var resp *awid.SendMessageResponse
		if beadsMailUsesCertSend(target.Kind, "") {
			resp, err = c.SendMessage(ctx, req)
		} else {
			resp, err = c.SendMessageByIdentity(ctx, req)
		}
		if err != nil {
			resp, err = gcMailRetryAsContinuation(ctx, c, target, req, err)
		}
		if err != nil {
			return gcMailError("%v", networkError(err, target.Value))
		}

		delegateMailAppendSendLogs(sel, resp, target.Value, subject, input.Body)
		return gcMailEmit(gcMailWireMessage{
			ID:        resp.MessageID,
			From:      gcMailSelfLabel(sel),
			To:        sanitizeDelegateMailDisplay(target.Value),
			Subject:   subject,
			Body:      input.Body,
			CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			ThreadID:  resp.ConversationID,
		})
	},
)

// gcMailReplyCmd implements `reply <id>`: a continuation of the source
// message's conversation. The recipient is never named — the server requires a
// continuation's signed recipient to match the conversation's, so the
// conversation id alone routes it (beads-mail record §8).
var gcMailReplyCmd = gcMailOp(
	"reply <message-id>",
	"Reply into a message's conversation (JSON on stdin, JSON message on stdout)",
	`Reads {"from":...,"subject":...,"body":...} on stdin and sends the body into
the conversation that <message-id> belongs to, then marks that message
read. An empty subject becomes "Re: <original subject>".

The reply goes to the conversation's counterparty by construction; there
is no recipient argument to get wrong.`,
	gcMailExactArgs(1, "aw gc-mail reply <message-id> < input.json"),
	func(cmd *cobra.Command, args []string) error {
		input, err := gcMailReadInput(cmd.InOrStdin())
		if err != nil {
			return err
		}
		messageID := strings.TrimSpace(args[0])

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, sel, err := gcMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		source, err := gcMailSourceMessage(ctx, c, messageID)
		if err != nil {
			return err
		}
		conversationID := strings.TrimSpace(source.ConversationID)
		if conversationID == "" {
			return gcMailError("message %s is legacy mail without a conversation; send a new message instead", sanitizeDelegateMailDisplay(messageID))
		}

		subject := strings.TrimSpace(input.Subject)
		if subject == "" {
			original := strings.TrimSpace(source.Subject)
			switch {
			case original == "":
				subject = "Re"
			case strings.HasPrefix(original, "Re: "):
				subject = original
			default:
				subject = "Re: " + original
			}
		}

		resp, err := c.SendMessageByIdentity(ctx, &awid.SendMessageRequest{
			ConversationID: conversationID,
			Subject:        subject,
			Body:           input.Body,
			Priority:       awid.PriorityNormal,
		})
		if err != nil {
			return gcMailError("%v", networkError(err, conversationID))
		}
		// A failed acknowledgement never fails the reply: retrying would
		// duplicate the reply. gc discards our stderr on success, so this
		// note is for a human running the command directly.
		if _, ackErr := c.AckMessage(ctx, messageID); ackErr != nil {
			fmt.Fprintf(os.Stderr, "note: reply was sent, but the source message could not be marked read: %s\n", sanitizeDelegateMailDisplay(ackErr.Error()))
		}
		// The label below is DISPLAY, not routing. Routing is done by the
		// shared client, which resolves the conversation's live participant
		// list at send time (cli/go/awid/mail.go's targetForMailConversation)
		// and signs THAT target into the envelope. This label is inferred
		// from the pre-send source message instead, because the send response
		// carries no recipient field to read back. aweb mail conversations
		// are 1:1, so the two agree; if they ever could not, the routed
		// target is the truthful one and this line is the one to fix.
		counterparty := delegateMailCounterpartyLabel(source, sel)
		delegateMailAppendSendLogs(sel, resp, counterparty, subject, input.Body)
		return gcMailEmit(gcMailWireMessage{
			ID:        resp.MessageID,
			From:      gcMailSelfLabel(sel),
			To:        sanitizeDelegateMailDisplay(counterparty),
			Subject:   subject,
			Body:      input.Body,
			CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			ThreadID:  resp.ConversationID,
		})
	},
)

// gcMailInboxCmd and gcMailCheckCmd are the same read-only unread listing.
// gc's Provider draws the distinction (Inbox may mark read, Check may not);
// here neither does, because reading is what marks read.
var gcMailInboxCmd = gcMailOp(
	"inbox [recipient]",
	"List unread messages as JSON (read-only)",
	`Lists this workspace's unread mail as a JSON array. Read-only: nothing is
marked read here.

gc passes the mailbox it wants ($GC_SESSION_ID, $GC_ALIAS, $GC_AGENT, or
"human"). This workspace has exactly one aweb identity, so the argument is
accepted and ignored — every gc session in this city shares one inbox.
That is the design record's §5 limitation, not a bug.`,
	gcMailRecipientArgs,
	func(cmd *cobra.Command, args []string) error { return gcMailList(cmd, true) },
)

var gcMailCheckCmd = gcMailOp(
	"check [recipient]",
	"List unread messages as JSON without marking anything read",
	`Identical to 'inbox' here: both are read-only unread listings. gc keeps the
two operations apart because a backend's inbox may mark messages read;
this one never does.`,
	gcMailRecipientArgs,
	func(cmd *cobra.Command, args []string) error { return gcMailList(cmd, true) },
)

var gcMailAllCmd = gcMailOp(
	"all [recipient]",
	"List all messages, read and unread, as JSON",
	`Lists one page of this workspace's mail, read and unread. gc's Provider
documents this as "all open messages"; aweb has no open/closed state, so
it is every message the inbox still holds within the server's retention
window.`,
	gcMailRecipientArgs,
	func(cmd *cobra.Command, args []string) error { return gcMailList(cmd, false) },
)

func gcMailList(cmd *cobra.Command, unreadOnly bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, _, err := gcMailReadClient(cmd, ctx)
	if err != nil {
		return err
	}
	resp, err := c.Inbox(ctx, awid.InboxParams{UnreadOnly: unreadOnly, Limit: gcMailPageLimit})
	if err != nil {
		return gcMailError("%v", err)
	}
	return gcMailEmit(gcMailWireList(resp.Messages))
}

// gcMailGetCmd retrieves one message without marking it read.
var gcMailGetCmd = gcMailOp(
	"get <message-id>",
	"Fetch one message as JSON without marking it read",
	`Fetches one message by id and leaves its read state alone. Visible for
messages this workspace sent as well as received.`,
	gcMailExactArgs(1, "aw gc-mail get <message-id>"),
	func(cmd *cobra.Command, args []string) error { return gcMailFetch(cmd, args[0], false) },
)

// gcMailReadCmd retrieves one message and marks it read.
var gcMailReadCmd = gcMailOp(
	"read <message-id>",
	"Fetch one message as JSON and mark it read",
	`Fetches one message by id and marks it read. Reading is what marks read
here, because aweb's read state drives the unread count and the wake path:
a displayed message that stayed unread would keep re-firing.

If the acknowledgement fails, this exits nonzero rather than reporting a
message as read that is not.`,
	gcMailExactArgs(1, "aw gc-mail read <message-id>"),
	func(cmd *cobra.Command, args []string) error { return gcMailFetch(cmd, args[0], true) },
)

func gcMailFetch(cmd *cobra.Command, ref string, markRead bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, sel, err := gcMailReadClient(cmd, ctx)
	if err != nil {
		return err
	}
	messageID := strings.TrimSpace(ref)
	msg, err := gcMailSourceMessage(ctx, c, messageID)
	if err != nil {
		return err
	}
	wire := gcMailWire(msg)
	if markRead && msg.ReadAt == nil {
		if _, ackErr := c.AckMessage(ctx, messageID); ackErr != nil {
			return gcMailError("message %s was fetched, but it could not be marked read: %v", sanitizeDelegateMailDisplay(messageID), ackErr)
		}
		wire.Read = true
		delegateMailLogReceived(sel, msg)
	}
	return gcMailEmit(wire)
}

// gcMailMarkReadCmd is the explicit acknowledgement.
var gcMailMarkReadCmd = gcMailOp(
	"mark-read <message-id>",
	"Mark one message read",
	`Marks one message read without displaying it. Emits nothing on success;
gc's protocol expects no output from this operation.`,
	gcMailExactArgs(1, "aw gc-mail mark-read <message-id>"),
	func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, _, err := gcMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		messageID := strings.TrimSpace(args[0])
		if _, err := c.AckMessage(ctx, messageID); err != nil {
			if code, ok := awid.HTTPStatusCode(err); ok && code == http.StatusNotFound {
				return gcMailNotFound(messageID)
			}
			return gcMailError("mark %s read: %v", sanitizeDelegateMailDisplay(messageID), err)
		}
		return nil
	},
)

// gcMailThreadCmd renders a conversation oldest-first. gc documents the
// argument as "a thread ID or any message ID in that thread", so both are
// accepted: an aweb conversation id is tried first, and anything the
// conversation endpoint does not know is looked up as a message and answered
// with its conversation.
var gcMailThreadCmd = gcMailOp(
	"thread <thread-id|message-id>",
	"List a conversation's messages as JSON, oldest first",
	`Renders one conversation as a JSON array, oldest first. The argument may be
an aweb conversation id (what this provider reports as thread_id) or any
message id inside it.`,
	gcMailExactArgs(1, "aw gc-mail thread <thread-id|message-id>"),
	func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, _, err := gcMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		id := strings.TrimSpace(args[0])
		resp, convErr := c.MailConversation(ctx, id, gcMailThreadLimit)
		if convErr != nil || resp == nil || len(resp.Messages) == 0 {
			msg, msgErr := gcMailSourceMessage(ctx, c, id)
			if msgErr != nil {
				if convErr != nil {
					return gcMailError("%v", convErr)
				}
				return msgErr
			}
			conversationID := strings.TrimSpace(msg.ConversationID)
			if conversationID == "" {
				return gcMailEmit([]gcMailWireMessage{gcMailWire(msg)})
			}
			resp, err = c.MailConversation(ctx, conversationID, gcMailThreadLimit)
			if err != nil {
				return gcMailError("%v", err)
			}
		}
		return gcMailEmit(gcMailWireList(resp.Messages))
	},
)

// gcMailCountCmd reports (total, unread). "Total" is what the inbox still
// holds within the retention window, paged up to a hard cap so a very large
// inbox cannot hang a gc command; the cap is stated in the help rather than
// silently truncating a number nobody can check.
var gcMailCountCmd = gcMailOp(
	"count [recipient]",
	"Report {\"total\":N,\"unread\":N} for this workspace",
	`Counts this workspace's mail. "Total" counts what the inbox holds inside
the server's retention window — aweb mail is delivery, not an archive, so
it is not a cumulative all-time total. Counting stops after 4000 messages; a larger
inbox reports that ceiling rather than a wrong number.`,
	gcMailRecipientArgs,
	func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, _, err := gcMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		total, unread := 0, 0
		cursor := ""
		for page := 0; page < gcMailCountPages; page++ {
			resp, err := c.Inbox(ctx, awid.InboxParams{Limit: gcMailPageLimit, Cursor: cursor})
			if err != nil {
				return gcMailError("%v", err)
			}
			for i := range resp.Messages {
				total++
				if resp.Messages[i].ReadAt == nil {
					unread++
				}
			}
			if !resp.HasMore || resp.NextCursor == "" {
				break
			}
			cursor = resp.NextCursor
		}
		return gcMailEmit(gcMailWireCount{Total: total, Unread: unread})
	},
)

// gcMailResolveCmd is not part of gc's protocol. It exists because the exec
// protocol leaves the provider no channel to disclose a resolution at send
// time: stdout carries JSON and gc discards stderr unless the exit code is
// nonzero. The per-city map is repo-controlled data that redirects mail
// carrying a verified identity, so there must be SOME way to see where a name
// goes before trusting it (design record §4).
var gcMailResolveCmd = &cobra.Command{
	Use:   "resolve <name>",
	Short: "Show the aweb address a recipient name resolves to",
	Long: `Prints where a gc recipient name would actually deliver, without sending
anything. This is the disclosure surface for the optional per-city map in
.gc/aweb-mail.toml: gc's exec protocol gives a provider no way to print a
"sent to X -> Y" line during 'gc mail send', so the resolution is
inspectable here instead.`,
	Args: gcMailExactArgs(1, "aw gc-mail resolve <name>"),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gcMailForceExitCode(func() error {
			addressMap, err := gcMailAddressMap()
			if err != nil {
				return err
			}
			target, err := resolveGCMailRecipient(addressMap, args[0])
			if err != nil {
				return err
			}
			source := "no map needed"
			if target.Mapped {
				source = addressMap.path
			}
			fmt.Printf("%s (%s, %s)\n", delegateMailResolutionNote(target), target.Kind, source)
			return nil
		}())
	},
}

// gcMailSubject derives the subject for a send. gc allows an empty subject
// (`gc mail send <to> "body"` passes none), while aweb mail is subject-first,
// so an empty one becomes the body's first line — the same choice the
// reference provider script makes for mcp_agent_mail.
func gcMailSubject(subject, body string) string {
	if trimmed := strings.TrimSpace(subject); trimmed != "" {
		return trimmed
	}
	line := strings.TrimSpace(body)
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	runes := []rune(line)
	if len(runes) > 72 {
		line = strings.TrimSpace(string(runes[:72])) + "..."
	}
	if line == "" {
		return "(no subject)"
	}
	return line
}

// gcMailSelfLabel names this workspace the way gcMailIdentityLabel names a
// correspondent, so a message's "from" round-trips as a recipient.
func gcMailSelfLabel(sel *awconfig.Selection) string {
	if sel == nil {
		return ""
	}
	return gcMailIdentityLabel(selectionAddress(sel), sel.DID, sel.Alias)
}

// gcMailRetryAsContinuation mirrors the bd delegate's server-directed
// continuation (beads-mail record §8): the server keeps one active mail
// conversation per pair and refuses a fresh one with HTTP 409, and a signed
// sender structurally cannot use the server's silent-reuse branch because the
// conversation id is part of what it signs.
func gcMailRetryAsContinuation(ctx context.Context, c *aweb.Client, target delegateMailTarget, req *awid.SendMessageRequest, sendErr error) (*awid.SendMessageResponse, error) {
	if code, ok := awid.HTTPStatusCode(sendErr); !ok || code != http.StatusConflict {
		return nil, sendErr
	}
	var conversation mailConversationTarget
	var err error
	switch target.Kind {
	case "address", "did":
		conversation, err = findUniqueMailConversationForTarget(ctx, c, target.Kind, target.Value)
	case "alias":
		if agent, found, findErr := clientAgentForAlias(ctx, c, target.Value); findErr == nil && found {
			conversation, err = findUniqueMailConversationForAgent(ctx, c, agent)
		}
	}
	if err != nil || conversation.conversationID == "" {
		return nil, sendErr
	}
	return c.SendMessageByIdentity(ctx, &awid.SendMessageRequest{
		ConversationID: conversation.conversationID,
		Subject:        req.Subject,
		Body:           req.Body,
		Priority:       req.Priority,
	})
}
