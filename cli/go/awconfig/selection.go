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
	RegistryURL   string
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
	var workspace *WorktreeWorkspace
	var teamState *TeamState
	var rootDir string
	var err error
	if identityHome != "" && opts.ExternalIdentityHome {
		workspace, teamState, rootDir, err = LoadWorkspaceAndTeamStateFromIdentityHome(identityHome)
	} else {
		workspace, teamState, rootDir, err = LoadWorkspaceAndTeamState(workingDir)
	}
	if err != nil {
		if workspace == nil && errors.Is(err, os.ErrNotExist) {
			// No workspace — check for a standalone identity (created by aw id create).
			identity, identityErr := loadSelectionIdentity(workingDir, identityHome)
			if identityErr == nil {
				return finalizeStandaloneIdentitySelection(workingDir, identityHome, opts.ExternalIdentityHome, identity)
			}
			return nil, errors.New("current directory is not initialized for aw; run `aw init` here or start with `aw run <provider>` in a TTY")
		}
		return nil, fmt.Errorf("invalid worktree workspace: %w", err)
	}

	identity, identityErr := loadSelectionIdentity(workingDir, identityHome)
	if identityErr != nil && !errors.Is(identityErr, os.ErrNotExist) {
		return nil, fmt.Errorf("invalid worktree identity: %w", identityErr)
	}
	verdict, err := decideWorkspaceSelection(workspaceSelectionFacts{
		Workspace:       workspace,
		TeamState:       teamState,
		BaseURLOverride: overrideBaseURL,
		TeamIDOverride:  opts.TeamIDOverride,
		ServerName:      opts.ServerName,
	})
	if err != nil {
		return nil, err
	}
	workspacePath := filepath.Join(rootDir, DefaultWorktreeWorkspaceRelativePath())
	if identityHome != "" {
		workspacePath = filepath.Join(identityHome, "workspace.yaml")
	}
	cert, err := loadSelectedTeamCertificate(workingDir, identityHome, verdict.Membership)
	if err != nil {
		return nil, err
	}
	selection := composeWorkspaceSelection(workspace, verdict.Membership, cert, identity)
	selection.WorkingDir = workingDir
	selection.IdentityHome = identityHome
	selection.ExternalIdentityHome = opts.ExternalIdentityHome
	selection.WorkspacePath = strings.TrimSpace(workspacePath)
	selection.ServerName = verdict.ServerName
	selection.BaseURL = verdict.BaseURL
	if strings.EqualFold(selection.Custody, "self") && workingDir != "" {
		selection.SigningKey = WorktreeSigningKeyPath(workingDir)
		if identityHome != "" {
			selection.SigningKey, err = IdentityHomePath(IdentityHome{Root: identityHome}, "signing.key")
			if err != nil {
				return nil, err
			}
		}
	}
	return &selection, nil
}

func loadSelectionIdentity(workingDir, identityHome string) (*WorktreeIdentity, error) {
	if identityHome == "" {
		identity, _, err := LoadWorktreeIdentityFromDir(workingDir)
		return identity, err
	}
	identityPath, err := IdentityHomePath(IdentityHome{Root: identityHome}, "identity.yaml")
	if err != nil {
		return nil, err
	}
	return LoadWorktreeIdentityFrom(identityPath)
}

// workspaceSelectionFacts holds what ResolveWorkspace read from a bound
// workspace. BaseURLOverride already carries any environment override.
type workspaceSelectionFacts struct {
	Workspace       *WorktreeWorkspace
	TeamState       *TeamState
	BaseURLOverride string
	TeamIDOverride  string
	ServerName      string
}

type workspaceSelectionVerdict struct {
	Membership *WorktreeMembership
	BaseURL    string
	ServerName string
}

// decideWorkspaceSelection selects the membership a command acts in, and the
// server it talks to: the requested team or else the active one, at the
// overriding URL or else the binding's.
func decideWorkspaceSelection(facts workspaceSelectionFacts) (workspaceSelectionVerdict, error) {
	baseURL := strings.TrimSpace(facts.Workspace.AwebURL)
	if override := strings.TrimSpace(facts.BaseURLOverride); override != "" {
		baseURL = override
	}
	membership := ActiveMembershipFor(facts.Workspace, facts.TeamState)
	if requested := strings.TrimSpace(facts.TeamIDOverride); requested != "" {
		membership = facts.Workspace.Membership(requested)
		if membership == nil {
			return workspaceSelectionVerdict{}, fmt.Errorf("team %q is not present in workspace memberships; available: %s", requested, strings.Join(facts.Workspace.AvailableTeamIDs(), ", "))
		}
	}
	if baseURL == "" {
		return workspaceSelectionVerdict{}, errors.New("worktree workspace binding is missing aweb_url")
	}
	if membership == nil || strings.TrimSpace(membership.TeamID) == "" {
		if facts.TeamState != nil && strings.TrimSpace(facts.TeamState.ActiveTeam) != "" {
			return workspaceSelectionVerdict{}, fmt.Errorf("active team %q is not in memberships; run aw id team switch <valid-team>", facts.TeamState.ActiveTeam)
		}
		return workspaceSelectionVerdict{}, errors.New("worktree workspace binding is missing active_team membership")
	}
	if err := ValidateBaseURL(baseURL); err != nil {
		return workspaceSelectionVerdict{}, fmt.Errorf("invalid base URL: %w", err)
	}
	serverName := strings.TrimSpace(facts.ServerName)
	if serverName == "" {
		derived, err := DeriveServerNameFromURL(baseURL)
		if err != nil {
			return workspaceSelectionVerdict{}, err
		}
		serverName = derived
	}
	return workspaceSelectionVerdict{Membership: membership, BaseURL: baseURL, ServerName: serverName}, nil
}

// loadSelectedTeamCertificate reads the selected membership's team certificate
// from its stored path; a missing certificate is nil.
func loadSelectedTeamCertificate(workingDir, identityHome string, membership *WorktreeMembership) (*awid.TeamCertificate, error) {
	certHome := WorktreeIdentityHome(workingDir)
	if identityHome != "" {
		certHome = identityHome
	}
	certPath, err := IdentityHomeStoredPath(IdentityHome{Root: certHome}, membership.CertPath)
	if err != nil {
		return nil, err
	}
	cert, err := awid.LoadTeamCertificate(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load active team certificate %s: %w", certPath, err)
	}
	return cert, nil
}

// composeWorkspaceSelection names the selected principal. The membership's
// team certificate is authoritative; the identity file fills what it lacks,
// except that a local identity never takes the file's stable id.
func composeWorkspaceSelection(workspace *WorktreeWorkspace, membership *WorktreeMembership, cert *awid.TeamCertificate, identity *WorktreeIdentity) Selection {
	selection := Selection{
		TeamID:      strings.TrimSpace(membership.TeamID),
		Alias:       strings.TrimSpace(membership.Alias),
		WorkspaceID: strings.TrimSpace(membership.WorkspaceID),
		AwebURL:     strings.TrimSpace(workspace.AwebURL),
	}
	selection.Domain, _ = splitTeamID(selection.TeamID)
	if cert != nil {
		selection.DID = strings.TrimSpace(cert.MemberDIDKey)
		selection.StableID = strings.TrimSpace(cert.MemberDIDAW)
		if scope := awid.NormalizeIdentityScope(cert.IdentityScope); scope == awid.IdentityModeLocal || scope == awid.IdentityModeGlobal {
			selection.IdentityScope = scope
		}
		selection.Address = strings.TrimSpace(cert.MemberAddress)
	}
	if identity == nil {
		return selection
	}
	if v := strings.TrimSpace(identity.Address); v != "" && selection.Address == "" {
		selection.Address = v
	}
	if v := strings.TrimSpace(identity.DID); v != "" && selection.DID == "" {
		selection.DID = v
	}
	if v := strings.TrimSpace(identity.IdentityScope); v != "" && selection.IdentityScope == "" {
		selection.IdentityScope = v
	}
	if v := strings.TrimSpace(identity.StableID); v != "" && selection.StableID == "" && selection.IdentityScope != awid.IdentityModeLocal {
		selection.StableID = v
	}
	selection.Custody = strings.TrimSpace(identity.Custody)
	selection.RegistryURL = strings.TrimSpace(identity.RegistryURL)
	if strings.TrimSpace(identity.Address) != "" {
		if authority, handle, ok := CutIdentityAddress(identity.Address); ok {
			if selection.Alias == "" {
				selection.Alias = handle
			}
			if selection.Domain == "" {
				selection.Domain = authority
			}
		}
	}
	return selection
}

func finalizeStandaloneIdentitySelection(workingDir, identityHome string, externalIdentityHome bool, identity *WorktreeIdentity) (*Selection, error) {
	did := strings.TrimSpace(identity.DID)
	stableID := strings.TrimSpace(identity.StableID)
	address := strings.TrimSpace(identity.Address)
	custody := strings.TrimSpace(identity.Custody)
	identityScope := strings.TrimSpace(identity.IdentityScope)
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
