package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type workspaceBindingInput struct {
	WorkingDir     string
	AwebURL        string
	CloudURL       string
	AwidURL        string
	ServerURL      string
	APIKey         string
	ProjectID      string
	ProjectSlug    string
	NamespaceSlug  string
	IdentityID     string
	IdentityHandle string
	DID            string
	StableID       string
	SigningKey     string
	Custody        string
	Lifetime       string
	HumanName      string
	Role           string
	AttachResult   *contextAttachResult
}

func persistWorkspaceBinding(input workspaceBindingInput) error {
	workingDir := strings.TrimSpace(input.WorkingDir)
	if workingDir == "" {
		return nil
	}
	statePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	state, err := awconfig.LoadWorktreeWorkspaceFrom(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		state = &awconfig.WorktreeWorkspace{}
	}

	if v := strings.TrimSpace(input.AwebURL); v != "" {
		state.AwebURL = v
		state.ServerURL = v
	}
	if v := strings.TrimSpace(input.CloudURL); v != "" {
		state.CloudURL = v
	}
	if v := strings.TrimSpace(input.AwidURL); v != "" {
		state.AwidURL = v
	}
	if v := strings.TrimSpace(input.ServerURL); v != "" {
		state.ServerURL = v
		if strings.TrimSpace(state.AwebURL) == "" {
			state.AwebURL = v
		}
	}
	if v := strings.TrimSpace(input.APIKey); v != "" {
		state.APIKey = v
	}
	if v := strings.TrimSpace(input.ProjectID); v != "" {
		state.ProjectID = v
	}
	if v := strings.TrimSpace(input.ProjectSlug); v != "" {
		state.ProjectSlug = v
		if strings.TrimSpace(state.NamespaceSlug) == "" {
			state.NamespaceSlug = v
		}
	}
	if v := strings.TrimSpace(input.NamespaceSlug); v != "" {
		state.NamespaceSlug = v
	}
	if v := strings.TrimSpace(input.IdentityID); v != "" {
		state.IdentityID = v
	}
	if v := strings.TrimSpace(input.IdentityHandle); v != "" {
		state.IdentityHandle = v
		state.Alias = v
	}
	lifetime := strings.TrimSpace(input.Lifetime)
	if lifetime != awid.LifetimePersistent {
		if v := strings.TrimSpace(input.DID); v != "" {
			state.DID = v
		}
		if v := strings.TrimSpace(input.StableID); v != "" {
			state.StableID = v
		}
		if v := strings.TrimSpace(input.SigningKey); v != "" {
			state.SigningKey = v
		}
		if v := strings.TrimSpace(input.Custody); v != "" {
			state.Custody = v
		}
		if lifetime != "" {
			state.Lifetime = lifetime
		}
	}
	if humanName := strings.TrimSpace(input.HumanName); humanName != "" {
		state.HumanName = humanName
	}
	if role := strings.TrimSpace(input.Role); role != "" {
		state.RoleName = role
		state.Role = role
	}

	if attach := input.AttachResult; attach != nil && attach.Workspace != nil {
		ws := attach.Workspace
		if v := strings.TrimSpace(ws.WorkspaceID); v != "" {
			state.WorkspaceID = v
		}
		if v := strings.TrimSpace(ws.ProjectID); v != "" {
			state.ProjectID = v
		}
		if v := strings.TrimSpace(ws.ProjectSlug); v != "" {
			state.ProjectSlug = v
			if state.NamespaceSlug == "" {
				state.NamespaceSlug = v
			}
		}
		if v := strings.TrimSpace(ws.Alias); v != "" {
			state.Alias = v
			if state.IdentityHandle == "" {
				state.IdentityHandle = v
			}
		}
		if v := strings.TrimSpace(ws.HumanName); v != "" {
			state.HumanName = v
		}
		if v := strings.TrimSpace(ws.Hostname); v != "" {
			state.Hostname = v
		}
		if v := strings.TrimSpace(ws.WorkspacePath); v != "" {
			state.WorkspacePath = v
		}
		switch strings.TrimSpace(attach.ContextKind) {
		case "repo_worktree":
			state.RepoID = strings.TrimSpace(ws.RepoID)
			state.CanonicalOrigin = strings.TrimSpace(ws.CanonicalOrigin)
			if v := strings.TrimSpace(ws.Role); v != "" {
				state.RoleName = v
				state.Role = v
			}
		case "local_dir":
			state.RepoID = ""
			state.CanonicalOrigin = ""
		}
	}

	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return awconfig.SaveWorktreeWorkspaceTo(statePath, state)
}
