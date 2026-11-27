package main

import "strings"

// formatShellCommand renders argv as one line a POSIX shell runs unchanged.
func formatShellCommand(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

// shellQuote leaves an argument bare only when every rune is one a POSIX
// shell passes through unchanged; anything else is single-quoted.
func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	for _, r := range arg {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("_@%+=:,./-", r) {
			continue
		}
		return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return arg
}
