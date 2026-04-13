package awconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type TeamMembership struct {
	TeamID   string `yaml:"team_id"`
	Alias    string `yaml:"alias,omitempty"`
	CertPath string `yaml:"cert_path"`
	JoinedAt string `yaml:"joined_at,omitempty"`
}

type TeamState struct {
	ActiveTeam  string           `yaml:"active_team,omitempty"`
	Memberships []TeamMembership `yaml:"memberships,omitempty"`
}

type teamStateYAML struct {
	ActiveTeam  string               `yaml:"active_team,omitempty"`
	Memberships []teamMembershipYAML `yaml:"memberships,omitempty"`
}

type teamMembershipYAML struct {
	TeamID   string `yaml:"team_id"`
	Alias    string `yaml:"alias,omitempty"`
	CertPath string `yaml:"cert_path"`
	JoinedAt string `yaml:"joined_at,omitempty"`
}

func (m *TeamMembership) normalize() {
	if m == nil {
		return
	}
	m.TeamID = strings.TrimSpace(m.TeamID)
	m.Alias = strings.TrimSpace(m.Alias)
	m.CertPath = filepath.ToSlash(strings.TrimSpace(m.CertPath))
	m.JoinedAt = strings.TrimSpace(m.JoinedAt)
}

func (s *TeamState) normalize() {
	if s == nil {
		return
	}
	s.ActiveTeam = strings.TrimSpace(s.ActiveTeam)
	normalized := make([]TeamMembership, 0, len(s.Memberships))
	for _, membership := range s.Memberships {
		membership.normalize()
		if membership.TeamID == "" && membership.CertPath == "" && membership.Alias == "" && membership.JoinedAt == "" {
			continue
		}
		normalized = append(normalized, membership)
	}
	s.Memberships = normalized
}

func (s *TeamState) validate() error {
	if s == nil {
		return errors.New("nil team state")
	}
	if len(s.Memberships) == 0 {
		return errors.New("teams.yaml must contain at least one membership")
	}
	if strings.TrimSpace(s.ActiveTeam) == "" {
		return errors.New("teams.yaml is missing active_team")
	}
	seen := make(map[string]struct{}, len(s.Memberships))
	for _, membership := range s.Memberships {
		if membership.TeamID == "" {
			return errors.New("teams.yaml membership is missing team_id")
		}
		if membership.CertPath == "" {
			return fmt.Errorf("teams.yaml membership %q is missing cert_path", membership.TeamID)
		}
		key := strings.ToLower(strings.TrimSpace(membership.TeamID))
		if _, ok := seen[key]; ok {
			return fmt.Errorf("teams.yaml contains duplicate membership for %q", membership.TeamID)
		}
		seen[key] = struct{}{}
	}
	if s.ActiveMembership() == nil {
		return fmt.Errorf("teams.yaml active_team %q is not present in memberships", s.ActiveTeam)
	}
	return nil
}

func (s *TeamState) Membership(teamID string) *TeamMembership {
	if s == nil {
		return nil
	}
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return nil
	}
	for i := range s.Memberships {
		if strings.EqualFold(strings.TrimSpace(s.Memberships[i].TeamID), teamID) {
			return &s.Memberships[i]
		}
	}
	return nil
}

func (s *TeamState) ActiveMembership() *TeamMembership {
	if s == nil {
		return nil
	}
	return s.Membership(s.ActiveTeam)
}

func (s *TeamState) AvailableTeamIDs() []string {
	if s == nil || len(s.Memberships) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(s.Memberships))
	teamIDs := make([]string, 0, len(s.Memberships))
	for _, membership := range s.Memberships {
		teamID := strings.TrimSpace(membership.TeamID)
		if teamID == "" {
			continue
		}
		key := strings.ToLower(teamID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		teamIDs = append(teamIDs, teamID)
	}
	sort.Strings(teamIDs)
	return teamIDs
}

func (s *TeamState) AddMembership(m TeamMembership) {
	if s == nil {
		return
	}
	m.normalize()
	if strings.TrimSpace(m.TeamID) == "" {
		return
	}
	for i := range s.Memberships {
		if strings.EqualFold(strings.TrimSpace(s.Memberships[i].TeamID), strings.TrimSpace(m.TeamID)) {
			s.Memberships[i] = m
			if strings.TrimSpace(s.ActiveTeam) == "" {
				s.ActiveTeam = m.TeamID
			}
			return
		}
	}
	s.Memberships = append(s.Memberships, m)
	if strings.TrimSpace(s.ActiveTeam) == "" {
		s.ActiveTeam = m.TeamID
	}
}

func (s *TeamState) RemoveMembership(teamID string) {
	if s == nil {
		return
	}
	teamID = strings.TrimSpace(teamID)
	if teamID == "" || len(s.Memberships) == 0 {
		return
	}
	filtered := make([]TeamMembership, 0, len(s.Memberships))
	removedActive := strings.EqualFold(strings.TrimSpace(s.ActiveTeam), teamID)
	for _, membership := range s.Memberships {
		if strings.EqualFold(strings.TrimSpace(membership.TeamID), teamID) {
			continue
		}
		filtered = append(filtered, membership)
	}
	s.Memberships = filtered
	if len(filtered) == 0 {
		s.ActiveTeam = ""
		return
	}
	if removedActive || s.ActiveMembership() == nil {
		s.ActiveTeam = strings.TrimSpace(filtered[0].TeamID)
	}
}

func (s *TeamState) UnmarshalYAML(value *yaml.Node) error {
	var raw teamStateYAML
	if err := value.Decode(&raw); err != nil {
		return err
	}
	memberships := make([]TeamMembership, 0, len(raw.Memberships))
	for _, membership := range raw.Memberships {
		memberships = append(memberships, TeamMembership{
			TeamID:   membership.TeamID,
			Alias:    membership.Alias,
			CertPath: membership.CertPath,
			JoinedAt: membership.JoinedAt,
		})
	}
	*s = TeamState{
		ActiveTeam:  raw.ActiveTeam,
		Memberships: memberships,
	}
	s.normalize()
	return s.validate()
}

func (s TeamState) MarshalYAML() (any, error) {
	s.normalize()
	if err := s.validate(); err != nil {
		return nil, err
	}
	memberships := make([]teamMembershipYAML, 0, len(s.Memberships))
	for _, membership := range s.Memberships {
		memberships = append(memberships, teamMembershipYAML{
			TeamID:   membership.TeamID,
			Alias:    membership.Alias,
			CertPath: membership.CertPath,
			JoinedAt: membership.JoinedAt,
		})
	}
	return teamStateYAML{
		ActiveTeam:  s.ActiveTeam,
		Memberships: memberships,
	}, nil
}

func DefaultTeamStateRelativePath() string {
	return filepath.Join(".aw", "teams.yaml")
}

func TeamStatePath(root string) string {
	return filepath.Join(filepath.Clean(root), DefaultTeamStateRelativePath())
}

func LoadTeamState(workingDir string) (*TeamState, error) {
	data, err := os.ReadFile(TeamStatePath(workingDir))
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		state, migrateErr := migrateTeamStateFromWorkspace(workingDir)
		if migrateErr != nil {
			if os.IsNotExist(migrateErr) {
				return nil, &os.PathError{
					Op:   "load teams state",
					Path: fmt.Sprintf("%s (neither teams.yaml nor workspace.yaml exists)", filepath.Join(filepath.Clean(workingDir), ".aw")),
					Err:  os.ErrNotExist,
				}
			}
			return nil, migrateErr
		}
		return state, nil
	}
	var state TeamState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func SaveTeamState(workingDir string, state *TeamState) error {
	if state == nil {
		return errors.New("nil team state")
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(TeamStatePath(workingDir), append(bytesTrimRightNewlines(data), '\n'))
}

func migrateTeamStateFromWorkspace(workingDir string) (*TeamState, error) {
	workspacePath := filepath.Join(filepath.Clean(workingDir), DefaultWorktreeWorkspaceRelativePath())
	workspace, err := LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil {
		return nil, err
	}
	state := teamStateFromWorkspace(workspace)
	if err := SaveTeamState(workingDir, state); err != nil {
		return nil, err
	}
	return state, nil
}

func teamStateFromWorkspace(workspace *WorktreeWorkspace) *TeamState {
	if workspace == nil {
		return nil
	}
	state := &TeamState{
		ActiveTeam: strings.TrimSpace(workspace.ActiveTeam),
	}
	for _, membership := range workspace.Memberships {
		state.Memberships = append(state.Memberships, TeamMembership{
			TeamID:   strings.TrimSpace(membership.TeamID),
			Alias:    strings.TrimSpace(membership.Alias),
			CertPath: filepath.ToSlash(strings.TrimSpace(membership.CertPath)),
			JoinedAt: strings.TrimSpace(membership.JoinedAt),
		})
	}
	state.normalize()
	return state
}
