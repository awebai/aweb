package run

import (
	"fmt"
	"strings"
)

func IdentityPromptLabel(projectSlug string, canonicalOrigin string, repoOrigin string, alias string) string {
	return DefaultInputPromptLabel
}

func StatusIdentity(provider string, projectSlug string, repoSlug string, alias string) string {
	provider = strings.TrimSpace(provider)
	projectSlug = strings.TrimSpace(projectSlug)
	repoSlug = strings.TrimSpace(repoSlug)
	alias = strings.TrimSpace(alias)

	var parts []string
	if projectSlug != "" {
		parts = append(parts, projectSlug)
	}
	if repoSlug != "" {
		parts = append(parts, repoSlug)
	}
	if alias != "" {
		parts = append(parts, alias)
	}
	identity := strings.Join(parts, ":")
	if provider != "" && identity != "" {
		return provider + "@" + identity
	}
	if provider != "" {
		return ""
	}
	return identity
}

func ComposeStatusLine(identity string, transient string) string {
	identity = strings.TrimSpace(identity)
	transient = strings.TrimSpace(transient)
	if identity == "" {
		return transient
	}
	if transient == "" {
		return identity
	}
	return identity + " · " + transient
}

func formatRunStatus(st *state) string {
	if st == nil || st.RunLabel == "" {
		return ""
	}
	var parts []string
	if st.CumulativeCostUSD > 0 {
		parts = append(parts, fmt.Sprintf("$%.2f", st.CumulativeCostUSD))
	}
	if st.Autofeed {
		parts = append(parts, "autofeed")
	}
	if strings.TrimSpace(st.NextPrompt) != "" {
		parts = append(parts, "queued")
	}
	switch st.ConnState {
	case ConnStreaming:
		parts = append(parts, "streaming")
	case ConnReconnecting:
		parts = append(parts, "reconnecting...")
	}
	return strings.Join(parts, " · ")
}

func formatWaitStatus(label string, st *state) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}

	parts := []string{label}
	if st != nil && st.Autofeed {
		parts = append(parts, "autofeed")
	}
	if st != nil {
		switch st.ConnState {
		case ConnStreaming:
			parts = append(parts, "streaming")
		case ConnReconnecting:
			parts = append(parts, "reconnecting...")
		}
	}
	return strings.Join(parts, " · ")
}

func ShortRepoName(canonicalOrigin string, repoOrigin string) string {
	for _, candidate := range []string{canonicalOrigin, repoOrigin} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		candidate = strings.TrimSuffix(candidate, ".git")
		candidate = strings.TrimSuffix(candidate, "/")
		candidate = strings.TrimSuffix(candidate, ":")
		candidate = strings.ReplaceAll(candidate, "\\", "/")
		if idx := strings.LastIndex(candidate, "/"); idx >= 0 && idx < len(candidate)-1 {
			return candidate[idx+1:]
		}
		if idx := strings.LastIndex(candidate, ":"); idx >= 0 && idx < len(candidate)-1 {
			return candidate[idx+1:]
		}
	}
	return ""
}
