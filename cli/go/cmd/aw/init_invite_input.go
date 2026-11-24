package main

import (
	"github.com/spf13/cobra"
	"strings"
)

// initInviteInput selects the same private token reader as team join. The
// command resolves selection and conflicts before reading any bearer bytes.
type initInviteInput struct {
	File  string
	Stdin bool
}

func (input initInviteInput) selected() bool { return input.File != "" || input.Stdin }

func readInitInviteInput(cmd *cobra.Command) (initInviteInput, error) {
	var input initInviteInput
	if cmd != nil {
		if cmd.Flags().Lookup("token-file") != nil {
			path, err := cmd.Flags().GetString("token-file")
			if err != nil {
				return input, err
			}
			input.File = strings.TrimSpace(path)
		}
		if cmd.Flags().Lookup("token-stdin") != nil {
			fromStdin, err := cmd.Flags().GetBool("token-stdin")
			if err != nil {
				return input, err
			}
			input.Stdin = fromStdin
		}
	}
	if input.File != "" && input.Stdin {
		return input, usageError("--token-file and --token-stdin cannot be used together")
	}
	if input.selected() && strings.TrimSpace(initInvite) != "" {
		return input, usageError("give the invite token through --invite or through --token-file or --token-stdin, not both")
	}
	return input, nil
}

func initInviteToken(cmd *cobra.Command, input initInviteInput) (string, error) {
	if !input.selected() {
		return initInvite, nil
	}
	args, err := teamJoinTokenArgs(cmd, nil)
	if err != nil {
		return "", err
	}
	if len(args) != 1 {
		return "", usageError("provide one invitation with --invite, --token-file or --token-stdin")
	}
	return args[0], nil
}
