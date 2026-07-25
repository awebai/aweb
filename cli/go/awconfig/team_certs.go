package awconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/awid"
)

type StoredTeamCertificate struct {
	TeamID      string
	CertPath    string
	Certificate *awid.TeamCertificate
}

func TeamCertificatesDir(worktreeDir string) string {
	return filepath.Join(WorktreeIdentityHome(worktreeDir), "team-certs")
}

func EncodeTeamIDForCertificatePath(teamID string) string {
	teamID = strings.TrimSpace(teamID)
	teamID = strings.ReplaceAll(teamID, "__", "____")
	teamID = strings.ReplaceAll(teamID, ":", "__")
	return teamID
}

func TeamCertificateRelativePath(teamID string) string {
	return filepath.ToSlash(filepath.Join("team-certs", EncodeTeamIDForCertificatePath(teamID)+".pem"))
}

func TeamCertificatePath(worktreeDir, teamID string) string {
	return filepath.Join(WorktreeIdentityHome(worktreeDir), filepath.FromSlash(TeamCertificateRelativePath(teamID)))
}

func TeamCertificatePathFromIdentityHome(identityHome, teamID string) (string, error) {
	return IdentityHomePath(IdentityHome{Root: identityHome}, TeamCertificateRelativePath(teamID))
}

func SaveTeamCertificateForTeam(worktreeDir, teamID string, cert *awid.TeamCertificate) (string, error) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return "", fmt.Errorf("team_id is required")
	}
	if cert == nil {
		return "", fmt.Errorf("certificate is required")
	}
	if strings.TrimSpace(cert.Team) != teamID {
		return "", fmt.Errorf("certificate team_id %q does not match %q", cert.Team, teamID)
	}
	certPath := TeamCertificatePath(worktreeDir, teamID)
	if err := preflightIdentityFile(certPath, "team certificate"); err != nil {
		return "", err
	}
	if err := awid.SaveTeamCertificate(certPath, cert); err != nil {
		return "", err
	}
	return TeamCertificateRelativePath(teamID), nil
}

func LoadTeamCertificateForTeam(worktreeDir, teamID string) (*awid.TeamCertificate, error) {
	path := TeamCertificatePath(worktreeDir, teamID)
	if err := preflightIdentityFile(path, "team certificate"); err != nil {
		return nil, err
	}
	return awid.LoadTeamCertificate(path)
}

func SaveTeamCertificateForTeamToIdentityHome(identityHome, teamID string, cert *awid.TeamCertificate) (string, error) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" || cert == nil || strings.TrimSpace(cert.Team) != teamID {
		return "", fmt.Errorf("certificate team_id does not match %q", teamID)
	}
	path, err := TeamCertificatePathFromIdentityHome(identityHome, teamID)
	if err != nil {
		return "", err
	}
	if err := awid.SaveTeamCertificate(path, cert); err != nil {
		return "", err
	}
	return TeamCertificateRelativePath(teamID), nil
}

func LoadTeamCertificateForTeamFromIdentityHome(identityHome, teamID string) (*awid.TeamCertificate, error) {
	path, err := TeamCertificatePathFromIdentityHome(identityHome, teamID)
	if err != nil {
		return nil, err
	}
	return awid.LoadTeamCertificate(path)
}

func ListTeamCertificates(worktreeDir string) ([]StoredTeamCertificate, error) {
	return listTeamCertificatesFromDir(TeamCertificatesDir(worktreeDir))
}

func ListTeamCertificatesFromIdentityHome(identityHome string) ([]StoredTeamCertificate, error) {
	return listTeamCertificatesFromDir(filepath.Join(filepath.Clean(identityHome), "team-certs"))
}

func listTeamCertificatesFromDir(dir string) ([]StoredTeamCertificate, error) {
	if err := preflightIdentityDir(dir, "team certificate directory"); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	stored := make([]StoredTeamCertificate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".pem" {
			continue
		}
		absPath := filepath.Join(dir, entry.Name())
		if err := preflightIdentityFile(absPath, "team certificate"); err != nil {
			return nil, err
		}
		cert, err := awid.LoadTeamCertificate(absPath)
		if err != nil {
			return nil, err
		}
		teamID := strings.TrimSpace(cert.Team)
		if teamID == "" {
			return nil, fmt.Errorf("certificate %s is missing team_id", absPath)
		}
		stored = append(stored, StoredTeamCertificate{
			TeamID:      teamID,
			CertPath:    TeamCertificateRelativePath(teamID),
			Certificate: cert,
		})
	}
	sort.Slice(stored, func(i, j int) bool {
		return stored[i].TeamID < stored[j].TeamID
	})
	return stored, nil
}
