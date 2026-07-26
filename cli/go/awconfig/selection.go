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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

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
	WorkingDir           string
	IdentityHome         string
	ExternalIdentityHome bool
	WorkspacePath        string
	ServerName           string
	BaseURL              string
	AwebURL              string

	TeamID        string
	WorkspaceID   string
	Alias         string
	Address       string
	Email         string
	Domain        string
	DID           string
	StableID      string
	SigningKey    string
	Custody       string
	IdentityScope string
	// Lifetime is a deprecated-read-compat mirror of IdentityScope for callers
	// still using persistent/ephemeral helpers during the config migration.
	Lifetime    string
	RegistryURL string
}

type ResolveOptions struct {
	ServerName string

	WorkingDir           string
	IdentityHome         string
	ExternalIdentityHome bool

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

	identityHome := strings.TrimSpace(opts.IdentityHome)
	workspace, teamState, rootDir, err := LoadWorkspaceAndTeamState(workingDir)
	if identityHome != "" && opts.ExternalIdentityHome {
		workspace, teamState, rootDir, err = LoadWorkspaceAndTeamStateFromIdentityHome(identityHome)
	}
	if err != nil {
		if workspace == nil && errors.Is(err, os.ErrNotExist) {
			// No workspace — check for a standalone identity (created by aw id create).
			var identity *WorktreeIdentity
			var identityErr error
			if identityHome != "" {
				identityPath, pathErr := IdentityHomePath(IdentityHome{Root: identityHome}, "identity.yaml")
				if pathErr != nil {
					identityErr = pathErr
				} else {
					identity, identityErr = LoadWorktreeIdentityFrom(identityPath)
				}
			} else {
				identity, _, identityErr = LoadWorktreeIdentityFromDir(workingDir)
			}
			if identityErr == nil {
				return finalizeStandaloneIdentitySelection(workingDir, identityHome, opts.ExternalIdentityHome, identity)
			}
			return nil, errors.New("current directory is not initialized for aw; run `aw init` here or start with `aw run <provider>` in a TTY")
		}
		return nil, fmt.Errorf("invalid worktree workspace: %w", err)
	}

	var identity *WorktreeIdentity
	var identityErr error
	if identityHome != "" {
		identityPath, pathErr := IdentityHomePath(IdentityHome{Root: identityHome}, "identity.yaml")
		if pathErr != nil {
			identityErr = pathErr
		} else {
			identity, identityErr = LoadWorktreeIdentityFrom(identityPath)
		}
	} else {
		identity, _, identityErr = LoadWorktreeIdentityFromDir(workingDir)
	}
	if identityErr != nil && !errors.Is(identityErr, os.ErrNotExist) {
		return nil, fmt.Errorf("invalid worktree identity: %w", identityErr)
	}

	baseURL := strings.TrimSpace(workspace.AwebURL)
	if overrideBaseURL != "" {
		baseURL = overrideBaseURL
	}
	selectedTeamID := strings.TrimSpace(opts.TeamIDOverride)
	activeMembership := ActiveMembershipFor(workspace, teamState)
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
		if strings.TrimSpace(teamState.ActiveTeam) != "" {
			return nil, fmt.Errorf("active team %q is not in memberships; run aw id team switch <valid-team>", teamState.ActiveTeam)
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
	workspacePath := filepath.Join(rootDir, DefaultWorktreeWorkspaceRelativePath())
	if identityHome != "" {
		workspacePath = filepath.Join(identityHome, "workspace.yaml")
	}
	return finalizeWorkspaceSelection(workingDir, identityHome, opts.ExternalIdentityHome, workspacePath, serverName, baseURL, workspace, teamState, identity, teamID)
}

func finalizeWorkspaceSelection(workingDir, identityHome string, externalIdentityHome bool, workspacePath, serverName, baseURL string, ws *WorktreeWorkspace, ts *TeamState, identity *WorktreeIdentity, selectedTeamID string) (*Selection, error) {
	domain := ""
	alias := ""
	workspaceID := ""
	teamID := ""
	address := ""
	did := ""
	stableID := ""
	signingKey := ""
	custody := ""
	identityScope := ""
	lifetime := ""
	registryURL := ""
	awebURL := ""
	if ws != nil {
		selectedMembership := ws.Membership(selectedTeamID)
		if selectedMembership == nil {
			selectedMembership = ActiveMembershipFor(ws, ts)
		}
		if selectedMembership != nil {
			teamID = strings.TrimSpace(selectedMembership.TeamID)
			teamDomain, _ := splitTeamID(teamID)
			domain = teamDomain
			alias = strings.TrimSpace(selectedMembership.Alias)
			workspaceID = strings.TrimSpace(selectedMembership.WorkspaceID)
			certHome := WorktreeIdentityHome(workingDir)
			if identityHome != "" {
				certHome = identityHome
			}
			certPath, pathErr := IdentityHomeStoredPath(IdentityHome{Root: certHome}, selectedMembership.CertPath)
			if pathErr != nil {
				return nil, pathErr
			}
			if cert, err := awid.LoadTeamCertificate(certPath); err == nil {
				if v := strings.TrimSpace(cert.MemberDIDKey); v != "" {
					did = v
				}
				stableID = strings.TrimSpace(cert.MemberDIDAW)
				if v := awid.NormalizeIdentityScope(firstNonEmpty(cert.IdentityScope, cert.Lifetime)); v == awid.IdentityModeLocal || v == awid.IdentityModeGlobal {
					identityScope = v
					lifetime = awid.LegacyLifetimeForIdentityScope(v)
				}
				if v := strings.TrimSpace(cert.MemberAddress); v != "" {
					address = v
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("load active team certificate %s: %w", certPath, err)
			}
		}
		awebURL = strings.TrimSpace(ws.AwebURL)
	}
	if identity != nil {
		if v := strings.TrimSpace(identity.Address); v != "" && address == "" {
			address = v
		}
		if v := strings.TrimSpace(identity.DID); v != "" && did == "" {
			did = v
		}
		if v := strings.TrimSpace(identity.IdentityScope); v != "" && identityScope == "" {
			identityScope = v
			lifetime = awid.LegacyLifetimeForIdentityScope(v)
		}
		if v := strings.TrimSpace(identity.StableID); v != "" && stableID == "" && identityScope != awid.IdentityModeLocal {
			stableID = v
		}
		if v := strings.TrimSpace(identity.Custody); v != "" {
			custody = v
		}
		if v := strings.TrimSpace(identity.Lifetime); v != "" && lifetime == "" {
			lifetime = v
			if identityScope == "" {
				identityScope = awid.NormalizeIdentityScope(v)
			}
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
			if identityHome != "" {
				var pathErr error
				signingKey, pathErr = IdentityHomePath(IdentityHome{Root: identityHome}, "signing.key")
				if pathErr != nil {
					return nil, pathErr
				}
			}
		}
	}
	return &Selection{
		WorkingDir:           strings.TrimSpace(workingDir),
		IdentityHome:         strings.TrimSpace(identityHome),
		ExternalIdentityHome: externalIdentityHome,
		WorkspacePath:        strings.TrimSpace(workspacePath),
		ServerName:           serverName,
		BaseURL:              baseURL,
		AwebURL:              awebURL,
		TeamID:               teamID,
		WorkspaceID:          workspaceID,
		Alias:                alias,
		Address:              address,
		Domain:               domain,
		DID:                  did,
		StableID:             stableID,
		SigningKey:           signingKey,
		Custody:              custody,
		IdentityScope:        identityScope,
		Lifetime:             lifetime,
		RegistryURL:          registryURL,
	}, nil
}

func finalizeStandaloneIdentitySelection(workingDir, identityHome string, externalIdentityHome bool, identity *WorktreeIdentity) (*Selection, error) {
	did := strings.TrimSpace(identity.DID)
	stableID := strings.TrimSpace(identity.StableID)
	address := strings.TrimSpace(identity.Address)
	custody := strings.TrimSpace(identity.Custody)
	identityScope := strings.TrimSpace(identity.IdentityScope)
	lifetime := strings.TrimSpace(identity.Lifetime)
	if lifetime == "" && identityScope != "" {
		lifetime = awid.LegacyLifetimeForIdentityScope(identityScope)
	}
	signingKey := ""
	if strings.EqualFold(custody, "self") {
		signingKey = WorktreeSigningKeyPath(workingDir)
		if identityHome != "" {
			path, err := IdentityHomePath(IdentityHome{Root: identityHome}, "signing.key")
			if err != nil {
				return nil, err
			}
			signingKey = path
		}
	}
	handle := ""
	if address != "" {
		if _, h, ok := CutIdentityAddress(address); ok {
			handle = h
		}
	}
	return &Selection{
		WorkingDir:           workingDir,
		IdentityHome:         strings.TrimSpace(identityHome),
		ExternalIdentityHome: externalIdentityHome,
		DID:                  did,
		StableID:             stableID,
		Address:              address,
		Alias:                handle,
		Domain:               domainFromAddress(address),
		SigningKey:           signingKey,
		Custody:              custody,
		IdentityScope:        identityScope,
		Lifetime:             lifetime,
		RegistryURL:          strings.TrimSpace(identity.RegistryURL),
	}, nil
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
