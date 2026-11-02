package main

import (
	"fmt"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var roomCmd = &cobra.Command{
	Use: "room", Short: "Read or post to the shared team room", GroupID: groupNetwork,
	Long: "Read or post signed announcements to the shared team room. " + awid.RoomDisclosure + " Each post notifies other current members once. Read the room for the full post; no reply is expected.",
}
var roomAfter, roomMessageID, roomSubject, roomBody, roomBodyFile string
var roomLimit int

var roomReadCmd = &cobra.Command{
	Use: "read", Short: "Read retained team room history", Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if roomLimit < 1 || roomLimit > 200 {
			return fmt.Errorf("--limit must be between 1 and 200")
		}
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		client, err := resolveClient()
		if err != nil {
			return err
		}
		if roomMessageID != "" {
			if roomAfter != "" {
				return fmt.Errorf("--message-id and --after are mutually exclusive")
			}
			out, err := client.RoomMessage(ctx, roomMessageID)
			if err != nil {
				return roomReadError(client.TeamID(), roomMessageID, err)
			}
			return writeOutput(commandStdout, out, formatRoomMessage)
		}
		out, err := client.ReadRoom(ctx, awid.RoomReadParams{After: roomAfter, Limit: roomLimit})
		if err != nil {
			return roomReadError(client.TeamID(), "", err)
		}
		return writeOutput(commandStdout, out, func(v any) string {
			history := v.(*awid.RoomHistory)
			if len(history.Messages) == 0 {
				if roomAfter != "" {
					return "No more room posts.\n"
				}
				return "The team room is empty. Post with: aw room post --subject ... --body-file ...\n"
			}
			var b strings.Builder
			for i := range history.Messages {
				b.WriteString(formatRoomMessage(&history.Messages[i]))
			}
			if history.HasMore {
				fmt.Fprintf(&b, "More history: aw room read --after %s\n", history.NextCursor)
			}
			return b.String()
		})
	},
}

var roomPostCmd = &cobra.Command{
	Use: "post", Short: "Post a signed announcement to the team room", Args: cobra.NoArgs,
	Long: "Post a signed announcement. " + awid.RoomDisclosure + " E2E room posts are unsupported.",
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := resolveMailBody(roomBody, roomBodyFile)
		if err != nil {
			return err
		}
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		client, err := resolveClient()
		if err != nil {
			return err
		}
		out, err := client.PostRoom(ctx, awid.RoomPostParams{Subject: roomSubject, Body: body})
		if err != nil {
			return err
		}
		return writeOutput(commandStdout, out, formatRoomMessage)
	},
}

func formatRoomMessage(v any) string {
	m := v.(*awid.RoomMessage)
	return fmt.Sprintf("[%s] %s — %s\n%s\nMessage: %s\n", m.VerificationStatus, m.FromAlias, m.Subject, m.Body, m.MessageID)
}

// Preserve the original HTTP class/detail for --json and diagnostics while
// giving the room's known access and lookup refusals readable terminal copy.
type roomReadFailure struct {
	message string
	cause   error
}

func (e *roomReadFailure) Error() string { return e.message }
func (e *roomReadFailure) Unwrap() error { return e.cause }

func roomReadError(team, messageID string, err error) error {
	detail := awid.DescribeError(err)
	message := ""
	if detail.HTTPStatus == 404 && messageID != "" && detail.Detail == "Not found" {
		message = fmt.Sprintf("No room post %s in your team.", messageID)
	} else if detail.HTTPStatus == 403 && (strings.HasPrefix(detail.Detail, "Agent not connected:") || detail.Detail == "Room requires current team membership") {
		message = fmt.Sprintf("You are no longer a member of %s, so you cannot read its room.", team)
	}
	if message == "" {
		return err
	}
	return &roomReadFailure{message: message, cause: err}
}

func init() {
	roomReadCmd.Flags().StringVar(&roomAfter, "after", "", "Continue from a room history cursor")
	roomReadCmd.Flags().IntVar(&roomLimit, "limit", 50, "Maximum posts per page (1-200)")
	roomReadCmd.Flags().StringVar(&roomMessageID, "message-id", "", "Read one exact room post")
	roomPostCmd.Flags().StringVar(&roomSubject, "subject", "", "Announcement subject")
	roomPostCmd.Flags().StringVar(&roomBody, "body", "", shellExpandedInlineHelp("Announcement body", "--body-file"))
	roomPostCmd.Flags().StringVar(&roomBodyFile, "body-file", "", safeFileInputHelp("announcement body"))
	roomCmd.AddCommand(roomReadCmd, roomPostCmd)
	rootCmd.AddCommand(roomCmd)
}
