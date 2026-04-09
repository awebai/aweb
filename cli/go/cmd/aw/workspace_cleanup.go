package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
)

type goneWorkspace struct {
	WorkspaceID      string
	Alias            string
	WorkspacePath    string
	IdentityDeleted  bool
	WorkspaceDeleted bool
	CleanupBlocked   string
}

// detectGoneWorkspaces checks for workspaces on this hostname whose paths
// no longer exist. Ephemeral identities are deleted; persistent identities
// keep their identity but lose the gone workspace record.
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

		// Identity lifecycle is managed by team membership (certificate revocation),
		// not by workspace cleanup. Skip identity deletion.
		g.IdentityDeleted = false

		deleteWorkspaceCtx, deleteWorkspaceCancel := context.WithTimeout(context.Background(), 5*time.Second)
		deleteWorkspaceErr := client.WorkspaceDelete(deleteWorkspaceCtx, ws.WorkspaceID)
		deleteWorkspaceCancel()
		if deleteWorkspaceErr != nil {
			g.CleanupBlocked = deleteWorkspaceErr.Error()
		} else {
			g.WorkspaceDeleted = true
		}

		deleted[ws.WorkspaceID] = true
		gone = append(gone, g)
	}

	return gone
}

func formatGoneWorkspaces(gone []goneWorkspace) string {
	if len(gone) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Gone workspace checks:\n")
	for _, g := range gone {
		details := make([]string, 0, 2)
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
