package awconfig

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awid"
)

func splitTeamID(teamID string) (string, string) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return "", ""
	}
	domain, name, err := awid.ParseTeamID(teamID)
	if err != nil {
		return "", ""
	}
	return domain, name
}

type Selection struct {
	WorkingDir    string
	WorkspacePath string
	ServerName    string
	BaseURL       string
	AwebURL       string

	TeamID      string
	WorkspaceID string
	Alias       string
	Address     string
	Email       string
	Domain      string
	DID         string
	StableID    string
	SigningKey  string
	Custody     string
	Lifetime    string
	RegistryURL string
}

type ResolveOptions struct {
	ServerName string

	WorkingDir string

	BaseURLOverride string

	TeamIDOverride string

	AllowEnvOverrides bool
}

func ResolveWorkspace(opts ResolveOptions) (*Selection, error) {
	workingDir := strings.TrimSpace(opts.WorkingDir)
	if workingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		workingDir = wd
	}

	overrideBaseURL := strings.TrimSpace(opts.BaseURLOverride)
	if opts.AllowEnvOverrides {
		if v := strings.TrimSpace(os.Getenv("AWEB_URL")); v != "" {
			overrideBaseURL = v
		}
	}

	workspace, workspacePath, err := LoadWorktreeWorkspaceFromDir(workingDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No workspace — check for a standalone identity (created by aw id create).
			if identity, _, identityErr := LoadWorktreeIdentityFromDir(workingDir); identityErr == nil {
				return finalizeStandaloneIdentitySelection(workingDir, identity), nil
			}
			return nil, errors.New("current directory is not initialized for aw; run `aw init` here or start with `aw run <provider>` in a TTY")
		}
		return nil, fmt.Errorf("invalid worktree workspace: %w", err)
	}

	var identity *WorktreeIdentity
	if loadedIdentity, _, identityErr := LoadWorktreeIdentityFromDir(workingDir); identityErr == nil {
		identity = loadedIdentity
	} else if !errors.Is(identityErr, os.ErrNotExist) {
		return nil, fmt.Errorf("invalid worktree identity: %w", identityErr)
	}

	baseURL := strings.TrimSpace(workspace.AwebURL)
	if overrideBaseURL != "" {
		baseURL = overrideBaseURL
	}
	selectedTeamID := strings.TrimSpace(opts.TeamIDOverride)
	activeMembership := workspace.ActiveMembership()
	selectedMembership := activeMembership
	if selectedTeamID != "" {
		selectedMembership = workspace.Membership(selectedTeamID)
		if selectedMembership == nil {
			return nil, fmt.Errorf("team %q is not present in workspace memberships; available: %s", selectedTeamID, strings.Join(workspace.AvailableTeamIDs(), ", "))
		}
	}
	teamID := ""
	if selectedMembership != nil {
		teamID = strings.TrimSpace(selectedMembership.TeamID)
	}
	if baseURL == "" {
		return nil, errors.New("worktree workspace binding is missing aweb_url")
	}
	if teamID == "" {
		if strings.TrimSpace(workspace.ActiveTeam) != "" {
			return nil, fmt.Errorf("active team %q is not in memberships; run aw id team switch <valid-team>", workspace.ActiveTeam)
		}
		return nil, errors.New("worktree workspace binding is missing active_team membership")
	}
	if err := ValidateBaseURL(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	serverName := strings.TrimSpace(opts.ServerName)
	if serverName == "" {
		derived, derr := DeriveServerNameFromURL(baseURL)
		if derr != nil {
			return nil, derr
		}
		serverName = derived
	}
	return finalizeWorkspaceSelection(workingDir, workspacePath, serverName, baseURL, workspace, identity, teamID), nil
}

func finalizeWorkspaceSelection(workingDir, workspacePath, serverName, baseURL string, ws *WorktreeWorkspace, identity *WorktreeIdentity, selectedTeamID string) *Selection {
	domain := ""
	alias := ""
	workspaceID := ""
	teamID := ""
	address := ""
	did := ""
	stableID := ""
	signingKey := ""
	custody := ""
	lifetime := ""
	registryURL := ""
	awebURL := ""
	if ws != nil {
		selectedMembership := ws.Membership(selectedTeamID)
		if selectedMembership == nil {
			selectedMembership = ws.ActiveMembership()
		}
		if selectedMembership != nil {
			teamID = strings.TrimSpace(selectedMembership.TeamID)
			teamDomain, _ := splitTeamID(teamID)
			domain = teamDomain
			alias = strings.TrimSpace(selectedMembership.Alias)
			workspaceID = strings.TrimSpace(selectedMembership.WorkspaceID)
			certPath := filepath.Join(workingDir, ".aw", filepath.FromSlash(strings.TrimSpace(selectedMembership.CertPath)))
			if cert, err := awid.LoadTeamCertificate(certPath); err == nil {
				if v := strings.TrimSpace(cert.MemberAddress); v != "" {
					address = v
				}
			}
		}
		awebURL = strings.TrimSpace(ws.AwebURL)
	}
	if identity != nil {
		if v := strings.TrimSpace(identity.Address); v != "" && address == "" {
			address = v
		}
		if v := strings.TrimSpace(identity.DID); v != "" {
			did = v
		}
		if v := strings.TrimSpace(identity.StableID); v != "" {
			stableID = v
		}
		if v := strings.TrimSpace(identity.Custody); v != "" {
			custody = v
		}
		if v := strings.TrimSpace(identity.Lifetime); v != "" {
			lifetime = v
		}
		if v := strings.TrimSpace(identity.RegistryURL); v != "" {
			registryURL = v
		}
		if alias == "" && strings.TrimSpace(identity.Address) != "" {
			if _, handle, ok := CutIdentityAddress(identity.Address); ok {
				alias = handle
			}
		}
		if domain == "" && strings.TrimSpace(identity.Address) != "" {
			if authority, _, ok := CutIdentityAddress(identity.Address); ok {
				domain = authority
			}
		}
		if strings.EqualFold(custody, "self") && strings.TrimSpace(workingDir) != "" {
			signingKey = WorktreeSigningKeyPath(workingDir)
		}
	}
	return &Selection{
		WorkingDir:    strings.TrimSpace(workingDir),
		WorkspacePath: strings.TrimSpace(workspacePath),
		ServerName:    serverName,
		BaseURL:       baseURL,
		AwebURL:       awebURL,
		TeamID:        teamID,
		WorkspaceID:   workspaceID,
		Alias:         alias,
		Address:       address,
		Domain:        domain,
		DID:           did,
		StableID:      stableID,
		SigningKey:    signingKey,
		Custody:       custody,
		Lifetime:      lifetime,
		RegistryURL:   registryURL,
	}
}

func finalizeStandaloneIdentitySelection(workingDir string, identity *WorktreeIdentity) *Selection {
	did := strings.TrimSpace(identity.DID)
	stableID := strings.TrimSpace(identity.StableID)
	address := strings.TrimSpace(identity.Address)
	custody := strings.TrimSpace(identity.Custody)
	lifetime := strings.TrimSpace(identity.Lifetime)
	signingKey := ""
	if strings.EqualFold(custody, "self") {
		signingKey = WorktreeSigningKeyPath(workingDir)
	}
	handle := ""
	if address != "" {
		if _, h, ok := CutIdentityAddress(address); ok {
			handle = h
		}
	}
	return &Selection{
		WorkingDir:  workingDir,
		DID:         did,
		StableID:    stableID,
		Address:     address,
		Alias:       handle,
		Domain:      domainFromAddress(address),
		SigningKey:  signingKey,
		Custody:     custody,
		Lifetime:    lifetime,
		RegistryURL: strings.TrimSpace(identity.RegistryURL),
	}
}

func domainFromAddress(address string) string {
	authority, _, ok := CutIdentityAddress(address)
	if !ok {
		return ""
	}
	return authority
}

func DeriveBaseURLFromServerName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("empty server name")
	}
	if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") {
		return name, nil
	}
	host := name
	isLocal := strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "[::1]")
	scheme := "https"
	if isLocal {
		scheme = "http"
	}
	return scheme + "://" + host, nil
}

func DeriveServerNameFromURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("url missing host: %q", raw)
	}
	return u.Host, nil
}

func ValidateBaseURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("empty base URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid base URL %q", raw)
	}
	return nil
}
