package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// aw gc-mail is the aweb-backed implementation of Gas City's exec mail
// provider contract (GC_MAIL=exec:<command>): gc forks the command once per
// operation as `<command> <op> [arg]`, writes a JSON object on its stdin for
// send and reply, and parses its stdout as JSON. Design record:
// docs/gascity-mail-provider.md. Contract verified against
// gastownhall/gascity @ c96e54a3ab890ca984755b7fc5b5290cba5122d5
// (internal/mail/exec/exec.go, internal/mail/exec/json.go,
// internal/mail/mail.go, cmd/gc/providers.go, cmd/gc/cmd_mail.go).
//
// This file is the frame: the wire types, the client, the exit-code contract,
// and the refusals. The operations live in gc_mail_ops.go.

// gcMailNotFoundMarker is the exact stderr token gc's exec provider looks for
// to turn a failed get/read/mark-read/mark-unread/reply into mail.ErrNotFound
// rather than a generic backend failure (exec.go's normalizeMessageError).
// Emitting it is part of the contract, not a convenience.
const gcMailNotFoundMarker = "gc-mail-error:not-found"

// gcMailBodyLimit bounds a body read from stdin, as the bd delegate does.
const gcMailBodyLimit = 10 << 20

// gcMailPageLimit is one inbox page. gc's Inbox/Check/All/Count take no
// pagination, so a listing is one page and Count pages up to gcMailCountPages.
const (
	gcMailPageLimit   = 200
	gcMailCountPages  = 20
	gcMailThreadLimit = 500
)

// gcMailMapSpec locates the optional per-city address map. gc pins the city
// root in GC_CITY (the reference provider script reads exactly that variable);
// the marker inside it is .gc, so an unset variable means walking up for a
// directory that contains one.
var gcMailMapSpec = delegateMailMapSpec{
	envVar:            "GC_CITY",
	envNamesMarkerDir: false,
	markerDir:         ".gc",
	fileName:          "aweb-mail.toml",
}

var gcMailCmd = &cobra.Command{
	Use:   "gc-mail",
	Short: "Mail for Gas City: the GC_MAIL exec provider backed by aweb",
	Long: `Mail for Gas City, across machines and organizations.

Gas City's mail is pluggable: GC_MAIL=exec:<command> makes gc delegate
every mail operation to a command. This is that command, backed by aweb —
durable delivery, recipients who can be offline, and messages signed by a
cryptographically verifiable identity.

Setup, once per city:

  npm i -g @awebai/aw
  aw init
  export GC_MAIL=exec:aw-gc-mail

'aw-gc-mail' is installed by the same npm package and runs this command.
GC_MAIL names a single command with no arguments, which is why the
launcher exists; 'exec:aw gc-mail' would look for a program literally
named "aw gc-mail".

This command speaks gc's JSON protocol on stdin/stdout. It is meant to be
run by gc, not by hand — but every operation is a plain subcommand, so
'aw gc-mail inbox' works for a look, and 'aw gc-mail resolve <name>'
shows where a recipient name would actually go.

Optional in-session wake-ups when mail arrives: aw init --setup-channel.`,
}

// gcMailClientError wraps a workspace/identity resolution failure with this
// provider's own guidance. A gc user meets this inside `gc mail`, where "run
// aw init here" alone can point at the wrong directory: aw resolves identity
// from the current directory only, and gc runs the provider with the cwd it
// happens to hold.
func gcMailClientError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w\n(gc mail note: run 'aw init' in this city, or attach an existing identity with AWEB_IDENTITY_HOME=<path-to-.aw>)", err)
}

// gcMailIdentifyTransport marks every provider request with its own
// User-Agent. Per beads-mail record §15 the wedge signal is carried on the
// transport and never in message content; this provider gets a distinct token
// from `aw-beads-mail` because it is a distinct adoption question — sharing
// one marker would make the two ecosystems' numbers indistinguishable.
func gcMailIdentifyTransport(c *aweb.Client) {
	if c != nil {
		c.SetUserAgent("aw-gc-mail/" + version)
	}
}

// gcMailError is the provider's error constructor. It exists so that no
// gc-mail path can ever exit 2: gc's exec provider treats exit code 2 as
// "unknown operation" and converts it to SUCCESS WITH EMPTY OUTPUT
// (exec.go's run()). usageError exits 2, so a usage failure raised anywhere
// under a known operation would be silently swallowed by gc and reported to
// the user as a successful no-op. Every failure of a known operation must
// exit 1.
func gcMailError(format string, args ...any) error {
	return &cliError{code: 1, msg: fmt.Sprintf(format, args...)}
}

// gcMailNotFound is the message-not-found failure, carrying gc's protocol
// marker so gc maps it to mail.ErrNotFound.
func gcMailNotFound(id string) error {
	return gcMailError("%s: no aweb mail message %s", gcMailNotFoundMarker, sanitizeDelegateMailDisplay(id))
}

// gcMailForceExitCode is the second half of the exit-2 guard: helpers shared
// with the bd delegate raise usageError (exit 2), so every gc-mail RunE result
// passes through here on its way out.
func gcMailForceExitCode(err error) error {
	if err == nil {
		return nil
	}
	if exitCode(err) == 2 {
		return &cliError{code: 1, msg: err.Error()}
	}
	return err
}

// gcMailOp declares one operation of the exec protocol.
//
// Flag parsing stays ENABLED even though gc's protocol is positional-only,
// because disabling it hands the command cobra's unparsed argv — including
// `aw`'s own root flags. `aw --identity-home <path> gc-mail send <to>` then
// arrives as three positional arguments and fails the arity check instead of
// running, which is exactly what the identity-home regression test caught.
func gcMailOp(use, short, long string, args cobra.PositionalArgs, run func(cmd *cobra.Command, args []string) error) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  args,
		RunE: func(cmd *cobra.Command, args []string) error {
			return gcMailForceExitCode(run(cmd, args))
		},
	}
}

// gcMailExactArgs is cobra.ExactArgs with an exit-1 error, since a wrong
// argument count under a known operation must not exit 2.
func gcMailExactArgs(n int, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return gcMailError("usage: %s", usage)
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return gcMailError("usage: %s", usage)
			}
		}
		return nil
	}
}

// gcMailRecipientArgs accepts gc's optional recipient argument. The recipient
// selects a mailbox on the gc side; this provider has exactly one aweb
// identity per workspace, so the argument is accepted and ignored for routing
// (design record §5). Refusing it would break `gc mail inbox`, whose default
// recipient is $GC_SESSION_ID.
func gcMailRecipientArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return gcMailError("usage: %s [recipient]", cmd.CommandPath())
	}
	return nil
}

// gcMailUnsupported declares an operation the design record decides against.
// It exits 1, never 2: exit 2 would make gc report the operation as having
// succeeded while nothing happened — the silent fake this project refuses.
func gcMailUnsupported(use, short, message string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return gcMailError("%s", message)
		},
	}
}

// --- wire types -------------------------------------------------------------

// gcMailWireMessage is gc's mail.Message as it crosses the exec boundary.
// Field names and JSON tags mirror internal/mail/mail.go exactly; fields aweb
// cannot honestly fill (reply_to, priority, cc, rig) are omitted rather than
// guessed, since gc's decoder tolerates their absence.
type gcMailWireMessage struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at,omitempty"`
	Read      bool   `json:"read"`
	ThreadID  string `json:"thread_id,omitempty"`
}

// gcMailWireInput is the JSON object gc writes to our stdin for send and
// reply (exec/json.go sendInput and replyInput, which are the same shape).
type gcMailWireInput struct {
	From    string `json:"from"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// gcMailWireCount is the count operation's stdout shape (exec/json.go
// countOutput).
type gcMailWireCount struct {
	Total  int `json:"total"`
	Unread int `json:"unread"`
}

// gcMailReadInput decodes the operation input from stdin. gc always sets
// stdin explicitly (to an empty reader when it has nothing to say), so an
// empty read is a real "no input", not an inherited terminal.
func gcMailReadInput(stdin io.Reader) (gcMailWireInput, error) {
	raw, err := io.ReadAll(io.LimitReader(stdin, gcMailBodyLimit+1))
	if err != nil {
		return gcMailWireInput{}, gcMailError("read operation input from stdin: %v", err)
	}
	if len(raw) > gcMailBodyLimit {
		return gcMailWireInput{}, gcMailError("operation input exceeds the %d MiB limit", gcMailBodyLimit>>20)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return gcMailWireInput{}, gcMailError("no JSON input on stdin; gc sends {\"from\":...,\"subject\":...,\"body\":...} for this operation")
	}
	var input gcMailWireInput
	if err := json.Unmarshal([]byte(trimmed), &input); err != nil {
		return gcMailWireInput{}, gcMailError("stdin is not the expected JSON object: %v", err)
	}
	return input, nil
}

// gcMailEmit writes one JSON value to stdout. The exec protocol gives the
// provider stdout for JSON and nothing else, so nothing may print here
// casually — and stderr is discarded by gc unless the exit code is nonzero,
// so it is not an alternative channel (design record §3).
func gcMailEmit(v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return gcMailError("encode result: %v", err)
	}
	fmt.Println(string(encoded))
	return nil
}

// --- message conversion -----------------------------------------------------

// gcMailIdentityLabel renders one side of a message as a name gc can display
// AND hand straight back to this provider as a recipient: the verified aweb
// address when there is one, else the DID, else the team-local alias. The
// per-city map is deliberately NOT applied in reverse here — a reverse-mapped
// label would be shorter but would stop round-tripping the moment the map
// changes, and every form emitted here re-resolves through §4 steps 2-5.
func gcMailIdentityLabel(address, did, alias string) string {
	for _, candidate := range []string{address, did, alias} {
		if value := strings.TrimSpace(candidate); value != "" {
			return sanitizeDelegateMailDisplay(value)
		}
	}
	return ""
}

// gcMailNormalizeTimestamp re-emits the server's created_at as RFC3339. gc
// decodes this field into a time.Time, so an unparseable value would fail the
// WHOLE message decode; an unrecognized format is dropped instead, costing a
// timestamp rather than the message.
func gcMailNormalizeTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano)
		}
	}
	return ""
}

// gcMailWire converts an aweb inbox message into gc's wire message. The body
// is sanitized the way the bd delegate sanitizes what it prints: gc renders
// this text straight to a terminal, and a verified sender is not a trusted
// one.
func gcMailWire(msg *awid.InboxMessage) gcMailWireMessage {
	if msg == nil {
		return gcMailWireMessage{}
	}
	return gcMailWireMessage{
		ID:        msg.MessageID,
		From:      gcMailIdentityLabel(msg.FromAddress, msg.FromDID, msg.FromAlias),
		To:        gcMailIdentityLabel(msg.ToAddress, msg.ToDID, msg.ToAlias),
		Subject:   sanitizeDelegateMailDisplay(msg.Subject),
		Body:      sanitizeDelegateMailBody(msg.Body),
		CreatedAt: gcMailNormalizeTimestamp(msg.CreatedAt),
		Read:      msg.ReadAt != nil,
		ThreadID:  msg.ConversationID,
	}
}

func gcMailWireList(messages []awid.InboxMessage) []gcMailWireMessage {
	out := make([]gcMailWireMessage, 0, len(messages))
	for i := range messages {
		out = append(out, gcMailWire(&messages[i]))
	}
	return out
}

// --- identity and addressing ------------------------------------------------

// gcMailReservedRecipients are the names gc reserves for itself. "human" is
// gc's operator mailbox and "controller" its own daemon; neither is an aweb
// alias, so letting them fall through to a same-team alias lookup would send
// mail to whoever happens to hold that name. They must be mapped explicitly.
var gcMailReservedRecipients = map[string]bool{"human": true, "controller": true}

// resolveGCMailRecipient applies the beads-mail record's §5 resolution order
// unchanged, with one gc-specific guard in front of it for gc's reserved
// names.
func resolveGCMailRecipient(m delegateMailAddressMap, input string) (delegateMailTarget, error) {
	trimmed := strings.TrimSpace(input)
	if _, mapped := m.entries[trimmed]; !mapped && gcMailReservedRecipients[strings.ToLower(trimmed)] {
		return delegateMailTarget{}, unmappedDelegateMailNameError(m, trimmed)
	}
	return resolveDelegateMailRecipient(m, trimmed)
}

// gcMailAddressMap loads the optional per-city map. gc runs this provider from
// whatever working directory it holds, so the city root comes from GC_CITY
// when gc set it and from a walk up otherwise.
func gcMailAddressMap() (delegateMailAddressMap, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return delegateMailAddressMap{spec: gcMailMapSpec}, gcMailError("locate the working directory: %v", err)
	}
	m, err := loadDelegateMailAddressMap(cwd, gcMailMapSpec)
	if err != nil {
		return delegateMailAddressMap{spec: gcMailMapSpec}, gcMailError("%v", err)
	}
	return m, nil
}

// gcMailReadClient resolves the workspace identity and a mail client for a
// read-side operation, with E2EE configured for reading exactly as the other
// mail read paths do.
func gcMailReadClient(cmd *cobra.Command, ctx context.Context) (*aweb.Client, *awconfig.Selection, error) {
	c, sel, err := resolveMailMessagingClientSelection()
	if err != nil {
		return nil, nil, gcMailClientError(err)
	}
	gcMailIdentifyTransport(c)
	if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
		return nil, nil, err
	}
	return c, sel, nil
}

// gcMailSourceMessage fetches one exact message through the sender-OR-
// recipient scoped exact-read endpoint, so a message this workspace SENT is
// visible too (the recipient-scoped inbox lookup is not enough — beads-mail
// record §8). A miss carries gc's not-found marker.
func gcMailSourceMessage(ctx context.Context, c *aweb.Client, messageID string) (*awid.InboxMessage, error) {
	resp, err := c.Message(ctx, messageID)
	if err != nil {
		// A 404 is the id being wrong, not the network being down, and gc
		// distinguishes the two off our stderr marker.
		if code, ok := awid.HTTPStatusCode(err); ok && code == http.StatusNotFound {
			return nil, gcMailNotFound(messageID)
		}
		return nil, gcMailError("%v", networkError(err, messageID))
	}
	if resp == nil || len(resp.Messages) == 0 {
		return nil, gcMailNotFound(messageID)
	}
	return &resp.Messages[0], nil
}

func init() {
	gcMailCmd.GroupID = groupNetwork

	gcMailCmd.AddCommand(
		gcMailEnsureRunningCmd,
		gcMailSendCmd,
		gcMailReplyCmd,
		gcMailInboxCmd,
		gcMailCheckCmd,
		gcMailAllCmd,
		gcMailGetCmd,
		gcMailReadCmd,
		gcMailMarkReadCmd,
		gcMailThreadCmd,
		gcMailCountCmd,
		gcMailResolveCmd,

		gcMailUnsupported("mark-unread <id>", "Not supported: read state cannot be cleared",
			"gc mail mark-unread is not supported: the aweb server has no way to clear read state, and read state drives the wake path. Use 'gc mail thread' or 'gc mail peek' for a look that changes nothing"),
		gcMailUnsupported("archive <id>", "Not supported: aweb mail is delivery, not storage",
			"gc mail archive is not supported: aweb mail cannot be removed on request; it expires under the server's retention policy. Use 'gc mail mark-read' to clear the unread count. Note that gc's own archive DELETES the message bead, which this provider deliberately will not imitate"),
		gcMailUnsupported("delete <id>", "Not supported: aweb mail is delivery, not storage",
			"gc mail delete is not supported: aweb mail cannot be removed on request; it expires under the server's retention policy. Use 'gc mail mark-read' to clear the unread count"),
	)

	rootCmd.AddCommand(gcMailCmd)
}
