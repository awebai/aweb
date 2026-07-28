package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestInlineLongTextFlagHelpWarnsAboutShellExpansion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		cmd      *cobra.Command
		flag     string
		safeFlag string
	}{
		{name: "mail send body", cmd: mailSendCmd, flag: "body", safeFlag: "--body-file"},
		{name: "mail reply body", cmd: mailReplyCmd, flag: "body", safeFlag: "--body-file"},
		{name: "exact-session chat body", cmd: chatSendCmd, flag: "body", safeFlag: "--body-file"},
		{name: "task comment body", cmd: taskCommentAddCmd, flag: "body", safeFlag: "--body-file"},
		{name: "instructions body", cmd: instructionsSetCmd, flag: "body", safeFlag: "--body-file"},
		{name: "signed request body", cmd: idRequestCmd, flag: "body", safeFlag: "--body-file"},
		{name: "role playbook", cmd: rolesAddCmd, flag: "playbook", safeFlag: "--playbook-file"},
		{name: "roles bundle JSON", cmd: rolesSetCmd, flag: "bundle-json", safeFlag: "--bundle-file"},
		{name: "task close reason", cmd: taskCloseCmd, flag: "reason", safeFlag: "--reason-file"},
		{name: "task create description", cmd: taskCreateCmd, flag: "description", safeFlag: "--description-file"},
		{name: "task create notes", cmd: taskCreateCmd, flag: "notes", safeFlag: "--notes-file"},
		{name: "task update description", cmd: taskUpdateCmd, flag: "description", safeFlag: "--description-file"},
		{name: "task update notes", cmd: taskUpdateCmd, flag: "notes", safeFlag: "--notes-file"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flag := tc.cmd.Flags().Lookup(tc.flag)
			if flag == nil {
				t.Fatalf("missing --%s flag", tc.flag)
			}
			for _, want := range []string{"double-quoted", "backticks", "$(...)", "before aw", tc.safeFlag} {
				if !strings.Contains(flag.Usage, want) {
					t.Errorf("--%s help %q does not contain %q", tc.flag, flag.Usage, want)
				}
			}
		})
	}
}

func TestPositionalLongTextHelpWarnsAboutShellExpansion(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{name: "chat send and wait", cmd: chatSendAndWaitCmd},
		{name: "chat send and leave", cmd: chatSendAndLeaveCmd},
		{name: "chat extend wait", cmd: chatExtendWaitCmd},
		{name: "A2A send", cmd: a2aSendCmd},
		{name: "task comment", cmd: taskCommentAddCmd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range []string{"double-quoted", "backticks", "$(...)", "before aw", "--body-file"} {
				if !strings.Contains(tc.cmd.Long, want) {
					t.Errorf("long help %q does not contain %q", tc.cmd.Long, want)
				}
			}
		})
	}
}

func TestPositionalMessageBodyFilePreservesShellSyntax(t *testing.T) {
	t.Parallel()

	bodyPath := filepath.Join(t.TempDir(), "body.md")
	want := "run `make test` with $(EXAMPLE) left untouched"
	if err := os.WriteFile(bodyPath, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{Use: "send <recipient> [message]"}
	cmd.Flags().String("body-file", "", "")
	if err := cmd.Flags().Set("body-file", bodyPath); err != nil {
		t.Fatal(err)
	}
	args := []string{"reviewer"}
	if err := exactArgsWithBodyFile(cmd, args); err != nil {
		t.Fatal(err)
	}
	got, err := resolvePositionalMessage(cmd, args)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("body=%q, want %q", got, want)
	}
}

func TestResolveLongTextFlagsReadsFile(t *testing.T) {
	t.Parallel()

	bodyPath := filepath.Join(t.TempDir(), "description.md")
	want := "inspect `config.ts` and preserve $(EXAMPLE)\n"
	if err := os.WriteFile(bodyPath, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{Use: "create"}
	cmd.Flags().String("description", "", "")
	cmd.Flags().String("description-file", "", "")
	if err := cmd.Flags().Set("description-file", bodyPath); err != nil {
		t.Fatal(err)
	}
	got, set, err := resolveLongTextFlags(cmd, "description", "description-file")
	if err != nil {
		t.Fatal(err)
	}
	if !set || got != want {
		t.Fatalf("body=%q set=%v, want %q set", got, set, want)
	}
}

func TestLongTextInputsOfferFileFlags(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  *cobra.Command
		flag string
	}{
		{name: "chat send and wait", cmd: chatSendAndWaitCmd, flag: "body-file"},
		{name: "chat send and leave", cmd: chatSendAndLeaveCmd, flag: "body-file"},
		{name: "chat extend wait", cmd: chatExtendWaitCmd, flag: "body-file"},
		{name: "A2A send", cmd: a2aSendCmd, flag: "body-file"},
		{name: "task close reason", cmd: taskCloseCmd, flag: "reason-file"},
		{name: "task create description", cmd: taskCreateCmd, flag: "description-file"},
		{name: "task create notes", cmd: taskCreateCmd, flag: "notes-file"},
		{name: "task update description", cmd: taskUpdateCmd, flag: "description-file"},
		{name: "task update notes", cmd: taskUpdateCmd, flag: "notes-file"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cmd.Flags().Lookup(tc.flag) == nil {
				t.Fatalf("%s is missing --%s", tc.cmd.CommandPath(), tc.flag)
			}
		})
	}
}
