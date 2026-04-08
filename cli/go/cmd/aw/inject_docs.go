package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	awDocsMarkerStart = "<!-- AWEB:START -->"
	awDocsMarkerEnd   = "<!-- AWEB:END -->"
)

type injectDocsResult struct {
	Created  []string
	Injected []string
	Errors   []string
}

func InjectAgentDocs(repoRoot string) *injectDocsResult {
	body, err := loadProjectInstructionsBody(repoRoot)
	if err != nil {
		return &injectDocsResult{Errors: []string{err.Error()}}
	}
	return InjectProvidedAgentDocs(repoRoot, body)
}

func InjectProvidedAgentDocs(repoRoot, body string) *injectDocsResult {
	result := &injectDocsResult{}
	candidates := []string{"CLAUDE.md", "AGENTS.md"}
	processed := map[string]bool{}
	injectedDocs := renderInjectedDocs(body)

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
			updated = strings.TrimRight(updated, "\n") + "\n\n" + injectedDocs
		} else {
			updated = injectedDocs
		}
		if err := os.WriteFile(resolved, []byte(updated), mode); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		result.Injected = append(result.Injected, name)
	}

	if len(processed) == 0 {
		path := filepath.Join(repoRoot, "AGENTS.md")
		if err := os.WriteFile(path, []byte(renderAgentsTemplate(body)), 0o644); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("AGENTS.md: %v", err))
		} else {
			result.Created = append(result.Created, "AGENTS.md")
		}
	}

	return result
}

func loadProjectInstructionsBody(workingDir string) (string, error) {
	client, _, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveProjectInstructions(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Document.BodyMD), nil
}

func renderInjectedDocs(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return awDocsMarkerStart + "\n" + awDocsMarkerEnd + "\n"
	}
	return awDocsMarkerStart + "\n" + body + "\n" + awDocsMarkerEnd + "\n"
}

func renderAgentsTemplate(body string) string {
	return "# Agent Instructions\n\n" + renderInjectedDocs(body)
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
		fmt.Printf("Created %s with aw project instructions\n", name)
	}
	for _, name := range result.Injected {
		fmt.Printf("Injected aw project instructions into %s\n", name)
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
