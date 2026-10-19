package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/awebai/aw/internal/termtext"
	"github.com/spf13/cobra"
)

func writeAttachmentFile(path string, data []byte) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := pathpreflight.PreflightFile(absolute, "attachment output", pathpreflight.Options{}); err != nil {
		return err
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(absolute)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func attachmentCommands(kind string) *cobra.Command {
	var messageID, outputPath, sessionID string
	group := &cobra.Command{Use: "attachment", Short: "Fetch managed message attachments as the authenticated participant"}
	fetch := &cobra.Command{Use: "fetch <attachment-id>", Short: "Fetch exact file bytes to an explicit new output path", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if messageID == "" || outputPath == "" {
			return usageError("--message-id and --output are required")
		}
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		client, selection, err := resolveMailMessagingClientSelection()
		if err != nil {
			return err
		}
		if err := configureClientE2EE(ctx, client, selection, false); err != nil {
			return err
		}
		var list []awid.AttachmentDescriptor
		if kind == "mail" {
			messages, err := client.Message(ctx, messageID)
			if err != nil {
				return err
			}
			for _, message := range messages.Messages {
				if message.MessageID == messageID && message.AttachmentsAvailable {
					list = message.Attachments
				}
			}
		} else {
			if sessionID == "" {
				return usageError("--session-id is required for chat attachment reads")
			}
			messages, err := client.ChatHistory(ctx, awid.ChatHistoryParams{SessionID: sessionID, MessageID: messageID, Limit: 1})
			if err != nil {
				return err
			}
			for _, message := range messages.Messages {
				if message.MessageID == messageID && message.AttachmentsAvailable {
					list = message.Attachments
				}
			}
		}
		var descriptor *awid.AttachmentDescriptor
		for i := range list {
			if list[i].ID == args[0] {
				descriptor = &list[i]
				break
			}
		}
		if descriptor == nil {
			return errors.New("attachment is not available in the authenticated message")
		}
		data, err := client.Client.FetchAttachment(ctx, kind, messageID, *descriptor)
		if err != nil {
			return err
		}
		if err := writeAttachmentFile(outputPath, data); err != nil {
			return err
		}
		result := map[string]any{"attachment_id": descriptor.ID, "message_id": messageID, "bytes": len(data), "output": outputPath}
		printOutput(result, func(any) string {
			return fmt.Sprintf("Saved attachment %s (%d bytes) to %s\n", termtext.Line(descriptor.ID), len(data), termtext.Line(outputPath))
		})
		return nil
	}}
	fetch.Flags().StringVar(&messageID, "message-id", "", "Message containing the attachment")
	fetch.Flags().StringVar(&outputPath, "output", "", "Explicit new file path (existing files and symlinks are refused)")
	if kind == "chat" {
		fetch.Flags().StringVar(&sessionID, "session-id", "", "Chat session containing the message")
	}
	group.AddCommand(fetch)
	return group
}

func init() {
	mailCmd.AddCommand(attachmentCommands("mail"))
	chatCmd.AddCommand(attachmentCommands("chat"))
}
