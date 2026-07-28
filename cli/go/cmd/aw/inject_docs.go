package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/agentdocs"
)

const (
	awDocsMarkerStart = agentdocs.MarkerStart
	awDocsMarkerEnd   = agentdocs.MarkerEnd
)

type injectDocsResult struct {
	Created  []string `json:"created,omitempty"`
	Injected []string `json:"injected,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

func InjectAgentDocs(repoRoot string) *injectDocsResult {
	body, err := loadTeamInstructionsBody(repoRoot)
	if err != nil {
		return &injectDocsResult{Errors: []string{err.Error()}}
	}
	return InjectProvidedAgentDocs(repoRoot, body)
}

func InjectAgentDocsAtIdentityHome(repoRoot string, identityHome awconfig.IdentityHome) *injectDocsResult {
	client, _, err := resolveClientSelectionAtIdentityHome(repoRoot, identityHome)
	if err != nil {
		return &injectDocsResult{Errors: []string{err.Error()}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := client.ActiveTeamInstructions(ctx)
	if err != nil {
		return &injectDocsResult{Errors: []string{err.Error()}}
	}
	return InjectProvidedAgentDocs(repoRoot, strings.TrimSpace(resp.Document.BodyMD))
}

func InjectProvidedAgentDocs(repoRoot, body string) *injectDocsResult {
	return writeProvidedAgentDocs(repoRoot, body, false)
}

func UpdateProvidedAgentDocs(repoRoot, body string) *injectDocsResult {
	return writeProvidedAgentDocs(repoRoot, body, true)
}

func writeProvidedAgentDocs(repoRoot, body string, existingMarkedOnly bool) *injectDocsResult {
	result := &injectDocsResult{}
	canonicalRoot, err := canonicalAgentDocsTargetRoot(repoRoot)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("target directory: %v", err))
		return result
	}
	candidates := []string{"CLAUDE.md", "AGENTS.md"}
	processed := map[string]bool{}
	foundCandidate := false
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
		foundCandidate = true

		resolved, err := resolveAgentDocsCandidate(canonicalRoot, path, name)
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			continue
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
		if existingMarkedOnly && !agentdocs.HasSingleMarkedBlock(string(content)) {
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

	if !foundCandidate && !existingMarkedOnly {
		path := filepath.Join(repoRoot, "AGENTS.md")
		if err := os.WriteFile(path, []byte(renderAgentsTemplate(body)), 0o644); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("AGENTS.md: %v", err))
		} else {
			result.Created = append(result.Created, "AGENTS.md")
			// Symlink CLAUDE.md → AGENTS.md so Claude Code picks up the same file.
			// Skip if CLAUDE.md already exists (don't clobber user state). Best-effort:
			// symlink failure isn't fatal; AGENTS.md alone still works for tools that
			// read it directly.
			claudePath := filepath.Join(repoRoot, "CLAUDE.md")
			if _, err := os.Lstat(claudePath); os.IsNotExist(err) {
				if err := os.Symlink("AGENTS.md", claudePath); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("CLAUDE.md symlink: %v", err))
				} else {
					result.Created = append(result.Created, "CLAUDE.md (symlink → AGENTS.md)")
				}
			}
		}
	}

	return result
}

func canonicalAgentDocsTargetRoot(repoRoot string) (string, error) {
	absolute, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}

func resolveAgentDocsCandidate(canonicalRoot, candidate, name string) (string, error) {
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	rel, err := filepath.Rel(canonicalRoot, resolved)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		requestedRoot, absErr := filepath.Abs(filepath.Dir(candidate))
		if absErr != nil {
			requestedRoot = filepath.Dir(candidate)
		}
		return "", fmt.Errorf("%s resolves outside requested directory %s: %s", name, requestedRoot, resolved)
	}
	return resolved, nil
}

func hasSingleMarkedAgentDocs(repoRoot string) (bool, error) {
	canonicalRoot, err := canonicalAgentDocsTargetRoot(repoRoot)
	if err != nil {
		return false, fmt.Errorf("target directory: %w", err)
	}
	processed := map[string]bool{}
	for _, name := range []string{"CLAUDE.md", "AGENTS.md"} {
		path := filepath.Join(repoRoot, name)
		_, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("%s: %w", name, err)
		}
		resolved, err := resolveAgentDocsCandidate(canonicalRoot, path, name)
		if err != nil {
			return false, err
		}
		if processed[resolved] {
			continue
		}
		processed[resolved] = true
		content, err := os.ReadFile(resolved)
		if err != nil {
			return false, fmt.Errorf("%s: %w", name, err)
		}
		if agentdocs.HasSingleMarkedBlock(string(content)) {
			return true, nil
		}
	}
	return false, nil
}

func loadTeamInstructionsBody(workingDir string) (string, error) {
	client, _, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveTeamInstructions(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Document.BodyMD), nil
}

func renderInjectedDocs(body string) string {
	return agentdocs.Render(body)
}

func renderAgentsTemplate(body string) string {
	return "# Agent Instructions\n\n" + renderInjectedDocs(body)
}

func removeInjectedDocs(content string) string {
	return agentdocs.RemoveAll(content)
}

func printInjectDocsResult(result *injectDocsResult) {
	if result == nil {
		return
	}
	for _, name := range result.Created {
		fmt.Printf("Created %s with aw team instructions\n", name)
	}
	for _, name := range result.Injected {
		fmt.Printf("Injected aw team instructions into %s\n", name)
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
