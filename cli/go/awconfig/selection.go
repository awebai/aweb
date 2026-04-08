package awconfig

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Selection struct {
	WorkingDir    string
	WorkspacePath string
	ServerName    string
	BaseURL       string
	AwebURL       string
	CloudURL      string
	AwidURL       string

	DefaultProject string
	IdentityID     string
	IdentityHandle string
	Address        string
	Email          string
	NamespaceSlug  string
	DID            string
	StableID       string
	SigningKey     string
	Custody        string
	Lifetime       string
}

type ResolveOptions struct {
	ServerName string

	WorkingDir string

	BaseURLOverride string

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
	teamAddress := strings.TrimSpace(workspace.TeamAddress)
	if baseURL == "" || teamAddress == "" {
		return nil, errors.New("worktree workspace binding is missing aweb_url or team_address")
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
	return finalizeWorkspaceSelection(workingDir, workspacePath, serverName, baseURL, workspace, identity), nil
}

func finalizeWorkspaceSelection(workingDir, workspacePath, serverName, baseURL string, ws *WorktreeWorkspace, identity *WorktreeIdentity) *Selection {
	namespaceSlug := ""
	defaultProject := ""
	identityHandle := ""
	identityID := ""
	address := ""
	did := ""
	stableID := ""
	signingKey := ""
	custody := ""
	lifetime := ""
	awebURL := ""
	cloudURL := ""
	awidURL := ""
	if ws != nil {
		awebURL = strings.TrimSpace(ws.AwebURL)
		cloudURL = strings.TrimSpace(ws.CloudURL)
		awidURL = strings.TrimSpace(ws.AwidURL)
		namespaceSlug = strings.TrimSpace(ws.NamespaceSlug)
		defaultProject = strings.TrimSpace(ws.ProjectSlug)
		identityHandle = strings.TrimSpace(ws.IdentityHandle)
		identityID = strings.TrimSpace(ws.IdentityID)
		did = strings.TrimSpace(ws.DID)
		stableID = strings.TrimSpace(ws.StableID)
		signingKey = strings.TrimSpace(ws.SigningKey)
		custody = strings.TrimSpace(ws.Custody)
		lifetime = strings.TrimSpace(ws.Lifetime)
		if namespaceSlug == "" {
			namespaceSlug = defaultProject
		}
		if identityHandle == "" {
			identityHandle = strings.TrimSpace(ws.Alias)
		}
	}
	if identity != nil {
		if v := strings.TrimSpace(identity.Address); v != "" {
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
		if strings.EqualFold(custody, "self") && strings.TrimSpace(workingDir) != "" {
			signingKey = WorktreeSigningKeyPath(workingDir)
		}
	}
	return &Selection{
		WorkingDir:     strings.TrimSpace(workingDir),
		WorkspacePath:  strings.TrimSpace(workspacePath),
		ServerName:     serverName,
		BaseURL:        baseURL,
		AwebURL:        awebURL,
		CloudURL:       cloudURL,
		AwidURL:        awidURL,
		DefaultProject: defaultProject,
		IdentityID:     identityID,
		IdentityHandle: identityHandle,
		Address:        address,
		NamespaceSlug:  namespaceSlug,
		DID:            did,
		StableID:       stableID,
		SigningKey:     signingKey,
		Custody:        custody,
		Lifetime:       lifetime,
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
		WorkingDir:     workingDir,
		DID:            did,
		StableID:       stableID,
		Address:        address,
		IdentityHandle: handle,
		SigningKey:     signingKey,
		Custody:        custody,
		Lifetime:       lifetime,
	}
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
