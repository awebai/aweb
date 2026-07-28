package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func shellExpandedInlineHelp(label, fileFlag string) string {
	return fmt.Sprintf("%s. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use %s for Markdown or command examples", label, fileFlag)
}

func safeFileInputHelp(label string) string {
	return fmt.Sprintf("Read %s from a file; safe for Markdown or command examples", label)
}

func exactArgsWithBodyFile(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("body-file") {
		if len(args) == 2 {
			return usageError("the positional message and --body-file are mutually exclusive")
		}
		return cobra.ExactArgs(1)(cmd, args)
	}
	return cobra.ExactArgs(2)(cmd, args)
}

func resolvePositionalMessage(cmd *cobra.Command, args []string) (string, error) {
	if !cmd.Flags().Changed("body-file") {
		return args[1], nil
	}
	path, _ := cmd.Flags().GetString("body-file")
	return resolveMailBody("", path)
}

func resolveLongTextFlags(cmd *cobra.Command, inlineFlag, fileFlag string) (string, bool, error) {
	inlineSet := cmd.Flags().Changed(inlineFlag)
	fileSet := cmd.Flags().Changed(fileFlag)
	if inlineSet && fileSet {
		return "", false, usageError("--%s and --%s are mutually exclusive", inlineFlag, fileFlag)
	}
	if inlineSet {
		value, _ := cmd.Flags().GetString(inlineFlag)
		return value, true, nil
	}
	if !fileSet {
		return "", false, nil
	}
	path, _ := cmd.Flags().GetString(fileFlag)
	data, err := readFileBounded(path, maxBodyFileBytes)
	if err != nil {
		return "", false, fmt.Errorf("read %s %q: %w", fileFlag, path, err)
	}
	value := string(data)
	if strings.TrimSpace(value) == "" {
		return "", false, usageError("%s %q is empty", fileFlag, path)
	}
	return value, true, nil
}
