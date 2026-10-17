package main

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Activity summaries (docs/agent-activity.md, "What a summary may contain").
// A summary comes from a fixed per-tool template, never from model text or raw
// tool arguments: a command line or a URL can carry a bearer token. The
// redactor is the second line of defence, not the first. These are the
// templates of channel-core's activity/summary.ts, with Codex's shell argv and
// apply_patch inputs added.

const activitySummaryMaxBytes = 120

var (
	activityFileVerbs = map[string]string{
		"Read": "Reading", "read": "Reading", "Write": "Writing", "write": "Writing",
		"Edit": "Editing", "MultiEdit": "Editing", "NotebookEdit": "Editing", "edit": "Editing",
	}
	activityShellTools  = map[string]bool{"Bash": true, "bash": true, "shell": true, "local_shell": true, "exec_command": true}
	activitySearchTools = map[string]bool{"Glob": true, "Grep": true, "grep": true, "find": true}
	activityShells      = map[string]bool{"bash": true, "sh": true, "zsh": true}
	activityProgram     = regexp.MustCompile(`^[A-Za-z0-9_./+-]+$`)
	activityControl     = regexp.MustCompile("[\u0000-\u001f\u007f-\u009f]")
	activitySecrets     = []*regexp.Regexp{
		regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
	}
	activityLongToken = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
	activityPatchFile = regexp.MustCompile(`(?m)^\*\*\* (?:Add|Update|Delete) File: (.+)$`)
)

// redactActivitySummary returns the summary, or "" when it is too long,
// multi-line or secret-shaped.
func redactActivitySummary(summary string) string {
	if summary == "" || len(summary) > activitySummaryMaxBytes || activityControl.MatchString(summary) {
		return ""
	}
	for _, shape := range activitySecrets {
		if shape.MatchString(summary) {
			return ""
		}
	}
	for _, token := range activityLongToken.FindAllString(summary, -1) {
		if strings.ContainsAny(token, "abcdefghijklmnopqrstuvwxyz") && strings.ContainsAny(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(token, "0123456789") {
			return ""
		}
	}
	return summary
}

// codexToolSummary is the template summary for one tool call, or "" when none applies.
func codexToolSummary(tool string, input json.RawMessage, workRoot string) string {
	var args map[string]any
	if json.Unmarshal(input, &args) != nil {
		args = map[string]any{}
	}
	var summary string
	switch {
	case activityFileVerbs[tool] != "":
		summary = activityFileSummary(activityFileVerbs[tool], args, workRoot)
	case activityShellTools[tool]:
		summary = activityShellSummary(args)
	case tool == "apply_patch":
		summary = activityPatchSummary(args, workRoot)
	case tool == "WebFetch":
		summary = "Fetching a page"
		if parsed, err := url.Parse(stringArg(args, "url")); err == nil && parsed.Hostname() != "" {
			summary = "Fetching " + parsed.Hostname()
		}
	case tool == "WebSearch":
		summary = "Searching the web"
	case activitySearchTools[tool]:
		summary = "Searching files"
	}
	return redactActivitySummary(summary)
}

func stringArg(args map[string]any, key string) string {
	value, _ := args[key].(string)
	return value
}

func activityDisplayPath(path, workRoot string) string {
	name := filepath.Base(path)
	if workRoot == "" || !filepath.IsAbs(workRoot) {
		return name
	}
	root := filepath.Clean(workRoot)
	absolute := path
	if !filepath.IsAbs(absolute) {
		absolute = filepath.Join(root, path)
	}
	absolute = filepath.Clean(absolute)
	if !strings.HasPrefix(absolute, root+string(filepath.Separator)) {
		return name
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return name
	}
	return relative
}

func activityVerbPath(verb, path, workRoot string) string {
	shown := verb + " " + activityDisplayPath(path, workRoot)
	if len(shown) <= activitySummaryMaxBytes {
		return shown
	}
	return verb + " " + filepath.Base(path)
}

func activityFileSummary(verb string, args map[string]any, workRoot string) string {
	for _, key := range []string{"file_path", "notebook_path", "path"} {
		if path := stringArg(args, key); path != "" {
			return activityVerbPath(verb, path, workRoot)
		}
	}
	return ""
}

// activityShellSummary names the program only: the first token of a command
// string, or of the script a shell's -c runs.
func activityShellSummary(args map[string]any) string {
	command := stringArg(args, "command")
	if command == "" {
		command = stringArg(args, "cmd")
	}
	if argv, ok := args["command"].([]any); ok && len(argv) > 0 {
		first, _ := argv[0].(string)
		command = first
		if len(argv) >= 3 && activityShells[filepath.Base(first)] && (argv[1] == "-c" || argv[1] == "-lc") {
			command, _ = argv[2].(string)
		}
	}
	fields := strings.Fields(command)
	if len(fields) == 0 || strings.Contains(fields[0], "=") || !activityProgram.MatchString(fields[0]) {
		return "Running a command"
	}
	return "Running " + filepath.Base(fields[0])
}

// activityPatchSummary names the first file a patch touches, from its header
// line only; the patch body is never read into a summary.
func activityPatchSummary(args map[string]any, workRoot string) string {
	if match := activityPatchFile.FindStringSubmatch(stringArg(args, "command")); match != nil {
		return activityVerbPath("Editing", strings.TrimSpace(match[1]), workRoot)
	}
	return "Editing files"
}
