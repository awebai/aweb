package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	awDocsMarkerStart = "<!-- AWEB:START -->"
	awDocsMarkerEnd   = "<!-- AWEB:END -->"
)

const awInjectedDocs = awDocsMarkerStart + `
## aWeb Coordination Rules

This project uses ` + "`aw`" + ` for agent coordination.

## Start Here

` + "```bash" + `
aw policy show
aw workspace status
aw work ready
aw mail inbox --unread-only
` + "```" + `

## Rules

- Use ` + "`aw`" + ` for coordination work
- Treat ` + "`.aw/workspace.yaml`" + ` as the repo-local coordination identity for this worktree
- Default to mail for non-blocking coordination: ` + "`aw mail send --to <agent> --body \"...\"`" + `
- Use chat when you need a synchronous answer: ` + "`aw chat pending`" + `, ` + "`aw chat send-and-wait <agent> \"...\"`" + `
- Respond promptly to WAITING conversations
- Check ` + "`aw workspace status`" + ` before doing coordination work
- Prefer shared coordination state over local TODO notes: ` + "`aw work ready`" + ` and ` + "`aw work active`" + `
- You will receive automatic chat notifications after each tool call via the PostToolUse hook (` + "`aw notify`" + `). Respond promptly when notified.

## Using Mail

` + "```bash" + `
aw mail send --to <alias> --body "message"
aw mail send --to <alias> --subject "API design" --body "message"
aw mail inbox --unread-only
aw mail ack --message-id <id>
` + "```" + `

## Using Chat

` + "```bash" + `
aw chat send-and-wait <alias> "question" --start-conversation
aw chat send-and-wait <alias> "response"
aw chat send-and-leave <alias> "thanks, got it"
aw chat pending
aw chat open <alias>
aw chat history <alias>
aw chat extend-wait <alias> "need more time"
` + "```" + `
` + awDocsMarkerEnd + `
`

const awAgentsTemplate = `# Agent Instructions

` + awInjectedDocs

type injectDocsResult struct {
	Created  []string
	Injected []string
	Errors   []string
}

func InjectAgentDocs(repoRoot string) *injectDocsResult {
	result := &injectDocsResult{}
	candidates := []string{"CLAUDE.md", "AGENTS.md"}
	processed := map[string]bool{}

	for _, name := range candidates {
		path := filepath.Join(repoRoot, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
			continue
		}

		resolved := path
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err = filepath.EvalSymlinks(path)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
				continue
			}
		}
		if processed[resolved] {
			continue
		}
		processed[resolved] = true

		content, err := os.ReadFile(resolved)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		mode := info.Mode().Perm()
		updated := removeInjectedDocs(string(content))
		if strings.TrimSpace(updated) != "" {
			updated = strings.TrimRight(updated, "\n") + "\n\n" + awInjectedDocs
		} else {
			updated = awInjectedDocs
		}
		if err := os.WriteFile(resolved, []byte(updated), mode); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		result.Injected = append(result.Injected, name)
	}

	if len(processed) == 0 {
		path := filepath.Join(repoRoot, "AGENTS.md")
		if err := os.WriteFile(path, []byte(awAgentsTemplate), 0o644); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("AGENTS.md: %v", err))
		} else {
			result.Created = append(result.Created, "AGENTS.md")
		}
	}

	return result
}

func removeInjectedDocs(content string) string {
	start := strings.Index(content, awDocsMarkerStart)
	end := strings.Index(content, awDocsMarkerEnd)
	if start == -1 || end == -1 || end < start {
		return content
	}
	end += len(awDocsMarkerEnd)
	before := strings.TrimRight(content[:start], "\n")
	after := strings.TrimLeft(content[end:], "\n")
	switch {
	case before == "":
		return after
	case after == "":
		return before
	default:
		return before + "\n\n" + after
	}
}

func printInjectDocsResult(result *injectDocsResult) {
	if result == nil {
		return
	}
	for _, name := range result.Created {
		fmt.Printf("Created %s with aw coordination instructions\n", name)
	}
	for _, name := range result.Injected {
		fmt.Printf("Injected aw coordination instructions into %s\n", name)
	}
	for _, msg := range result.Errors {
		fmt.Fprintf(os.Stderr, "Warning: could not inject docs: %s\n", msg)
	}
}

func resolveRepoRoot(workingDir string) string {
	if root, err := currentGitWorktreeRootFromDir(workingDir); err == nil {
		return root
	}
	return workingDir
}
