package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// refreshOwnTeamCertificate runs when a server refuses home's certificate for
// team as team_key_not_current: the team's key changed and the key change
// issued this member a certificate under the new key. It reads the
// certificate the registry now records for the member's alias, fetches it and
// installs it through installTeamCertificateFile, which checks it against the
// team's current key and registration and replaces only a certificate under a
// superseded key. It returns the installed certificate's header, or "" when
// the registry records no other certificate for the member.
// refreshingTeamCertificate is set while this process refreshes a team
// certificate: a request the refresh itself makes is never refreshed again.
var refreshingTeamCertificate atomic.Bool

func refreshOwnTeamCertificate(ctx context.Context, sel *awconfig.Selection, home string) (string, error) {
	if !refreshingTeamCertificate.CompareAndSwap(false, true) {
		return "", nil
	}
	defer refreshingTeamCertificate.Store(false)
	team := strings.TrimSpace(sel.TeamID)
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(sel.WorkspacePath)
	if err != nil {
		return "", fmt.Errorf("read the workspace binding %s: %w", sel.WorkspacePath, err)
	}
	held, err := loadWorkspaceTeamCertificate(sel, workspace)
	if err != nil {
		return "", err
	}
	key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	if err != nil {
		return "", fmt.Errorf("load the signing key in %s: %w", home, err)
	}
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return "", err
	}
	registryURL := strings.TrimSpace(sel.RegistryURL)
	if registryURL == "" {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	} else if err := registry.TrustRegistryOrigin(registryURL); err != nil {
		return "", err
	}
	domain, name, err := awid.ParseTeamID(team)
	if err != nil {
		return "", err
	}
	member, err := registry.ResolveTeamMember(ctx, registryURL, domain, name, held.Alias, key)
	if err != nil {
		return "", fmt.Errorf("read the certificate the registry records for %s in %s: %w", held.Alias, team, err)
	}
	if strings.TrimSpace(member.CertificateID) == strings.TrimSpace(held.CertificateID) {
		return "", nil
	}
	cert, err := registry.FetchTeamCertificate(ctx, registryURL, domain, name, member.CertificateID, key)
	if err != nil {
		return "", fmt.Errorf("fetch certificate %s of %s: %w", member.CertificateID, team, err)
	}
	// The workspace binding names the certificate its clients present, so it
	// is pointed at the new one before the install sends anything with it.
	if _, err := installTeamCertificateFile(ctx, teamCertificateInstall{
		WorkingDir: sel.WorkingDir, Home: home, Certificate: cert, Replacement: replaceSupersededCertificate,
		WorkspacePath: sel.WorkspacePath, RegistryURL: registryURL, Registry: registry,
	}); err != nil {
		return "", err
	}
	return awid.EncodeTeamCertificateHeader(cert)
}
