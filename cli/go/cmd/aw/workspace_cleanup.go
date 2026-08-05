package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
)

type goneWorkspace struct {
	WorkspaceID    string
	Alias          string
	WorkspacePath  string
	CleanupStatus  string
	CleanupBlocked string
}

// detectGoneWorkspaces checks for workspaces on this hostname whose paths
// no longer exist. Path absence is informational: identity scope does not say
// whether the identity should be retired.
func detectGoneWorkspaces(client *aweb.Client, selfWorkspaceID string) []goneWorkspace {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.WorkspaceList(ctx, aweb.WorkspaceListParams{
		Hostname:        hostname,
		IncludePresence: false,
	})
	if err != nil {
		return nil
	}

	var gone []goneWorkspace
	seen := map[string]bool{}

	for _, ws := range resp.Workspaces {
		path := derefString(ws.WorkspacePath)
		if path == "" || ws.WorkspaceID == selfWorkspaceID {
			continue
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			continue
		}
		if seen[ws.WorkspaceID] {
			continue
		}

		g := goneWorkspace{
			WorkspaceID:   ws.WorkspaceID,
			Alias:         ws.Alias,
			WorkspacePath: path,
		}

		scope := workspaceIdentityScope(ws)
		switch scope {
		case "local":
			g.CleanupStatus = "gone_local_path_only"
			g.CleanupBlocked = "local identity path unavailable; explicit membership retirement required"
		case "global":
			g.CleanupStatus = "gone_global_path_only"
			g.CleanupBlocked = "global identity path unavailable; no cleanup attempted"
		default:
			g.CleanupStatus = "unknown_identity_scope_no_cleanup"
			g.CleanupBlocked = "identity scope unknown; no cleanup attempted"
		}

		seen[ws.WorkspaceID] = true
		gone = append(gone, g)
	}

	return gone
}

func workspaceIdentityScope(ws aweb.WorkspaceInfo) string {
	return strings.TrimSpace(derefString(ws.AgentIdentityScope))
}

func workspaceDeleteProtectiveReason(err error) (string, string) {
	status, ok := awid.HTTPStatusCode(err)
	if !ok || status != 409 {
		return "", ""
	}
	body, ok := awid.HTTPErrorBody(err)
	if !ok || strings.TrimSpace(body) == "" {
		return "", ""
	}
	var envelope struct {
		Detail json.RawMessage `json:"detail"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil || len(envelope.Detail) == 0 {
		return "", ""
	}
	var detail struct {
		Code                string `json:"code"`
		RecommendedNextStep string `json:"recommended_next_step"`
	}
	if json.Unmarshal(envelope.Detail, &detail) != nil || strings.TrimSpace(detail.Code) == "" {
		return "", ""
	}
	reason := strings.TrimSpace(detail.Code)
	if nextStep := strings.TrimSpace(detail.RecommendedNextStep); nextStep != "" {
		reason += ": " + nextStep
	}
	return strings.TrimSpace(detail.Code), reason
}

func formatGoneWorkspaces(gone []goneWorkspace) string {
	if len(gone) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Gone workspace checks:\n")
	for _, g := range gone {
		details := make([]string, 0, 2)
		if g.CleanupStatus != "" {
			details = append(details, g.CleanupStatus)
		}
		if len(details) == 0 {
			details = append(details, "detected gone workspace")
		}
		if g.CleanupBlocked != "" {
			details = append(details, "left workspace record intact: "+g.CleanupBlocked)
		}
		sb.WriteString(fmt.Sprintf("  %s (%s) — %s\n", g.Alias, abbreviateUserHome(g.WorkspacePath), strings.Join(details, ", ")))
	}
	return sb.String()
}
