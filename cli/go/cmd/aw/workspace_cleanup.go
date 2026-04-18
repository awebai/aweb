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
	WorkspaceID      string
	Alias            string
	WorkspacePath    string
	CleanupStatus    string
	IdentityDeleted  bool
	WorkspaceDeleted bool
	CleanupBlocked   string
}

// detectGoneWorkspaces checks for workspaces on this hostname whose paths
// no longer exist. The server owns cleanup policy and deletes the bound
// ephemeral identity when the stale workspace is removed.
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
	deleted := map[string]bool{}

	for _, ws := range resp.Workspaces {
		path := derefString(ws.WorkspacePath)
		if path == "" || ws.WorkspaceID == selfWorkspaceID {
			continue
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			continue
		}
		if deleted[ws.WorkspaceID] {
			continue
		}

		g := goneWorkspace{
			WorkspaceID:   ws.WorkspaceID,
			Alias:         ws.Alias,
			WorkspacePath: path,
		}

		lifetime := strings.TrimSpace(derefString(ws.AgentLifetime))
		switch lifetime {
		case "ephemeral":
			g.CleanupStatus = "gone_ephemeral_cleanup_candidate"
		case "persistent":
			g.CleanupStatus = "gone_persistent_path_only"
			g.CleanupBlocked = "persistent identity path unavailable; no cleanup attempted"
			deleted[ws.WorkspaceID] = true
			gone = append(gone, g)
			continue
		default:
			g.CleanupStatus = "unknown_lifetime_no_cleanup"
			g.CleanupBlocked = "identity lifetime unknown; no cleanup attempted"
			deleted[ws.WorkspaceID] = true
			gone = append(gone, g)
			continue
		}

		deleteWorkspaceCtx, deleteWorkspaceCancel := context.WithTimeout(context.Background(), 5*time.Second)
		deleteResp, deleteWorkspaceErr := client.WorkspaceDelete(deleteWorkspaceCtx, ws.WorkspaceID)
		deleteWorkspaceCancel()
		if deleteWorkspaceErr != nil {
			if code, reason := workspaceDeleteProtectiveReason(deleteWorkspaceErr); code != "" {
				switch code {
				case "persistent_identity_not_cleanup_eligible":
					g.CleanupStatus = "gone_persistent_path_only"
				case "unknown_lifetime_no_cleanup":
					g.CleanupStatus = "unknown_lifetime_no_cleanup"
				}
				g.CleanupBlocked = reason
			} else {
				g.CleanupBlocked = deleteWorkspaceErr.Error()
			}
		} else {
			if deleteResp != nil {
				g.IdentityDeleted = deleteResp.IdentityDeleted
			}
			g.WorkspaceDeleted = true
		}

		deleted[ws.WorkspaceID] = true
		gone = append(gone, g)
	}

	return gone
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
		details := make([]string, 0, 3)
		if g.CleanupStatus != "" {
			details = append(details, g.CleanupStatus)
		}
		if g.IdentityDeleted {
			details = append(details, "deleted ephemeral identity")
		}
		if g.WorkspaceDeleted {
			details = append(details, "removed workspace record")
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
