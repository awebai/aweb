package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The registries the operator named on the current command line.
func commandLineRegistryOrigins() []string {
	values := []string{
		a2aCardRegistry, a2aPublishRegistry, initAWIDRegistry,
		idAddressClaimRegistryURL, idChildRegistry, idCreateRegistryURL, idHumanInitRegistry, idHumanRegisterRegistry,
		idNamespaceDeleteAddressRegistry, idNamespaceDeleteRegistry, idNamespacePrepareControllerRegistryURL,
		idNamespaceReaffirmRegistry, idParentRegistry,
		teamCreateRegistryURL, teamDeleteRegistryURL, teamFetchCertRegistry, teamHumanCreateRegistryURL,
		teamHumanRemoveRegistryURL, teamHumanReplaceKeyRegistryURL, teamInstallCertRegistry, teamMembersRegistryURL,
		teamRegisterRegistryURL, teamReissueCertRegistryURL, teamRemoveRegistryURL, teamRotateKeyRegistryURL,
		teamSetServerRegistryURL, teamShowServerRegistry, whoRegistry, verifyRegistry,
	}
	origins := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			origins = append(origins, value)
		}
	}
	return origins
}

// trustCommandLineRegistries marks the command line's registries as the
// operator's explicit choice on r. An invalid value is not trusted; the
// command that uses it reports it.
func trustCommandLineRegistries(r *awid.RegistryResolver) {
	if r == nil {
		return
	}
	for _, origin := range commandLineRegistryOrigins() {
		_ = r.TrustRegistryOrigin(origin)
	}
}

// newAWIDRegistryClient is awid.NewAWIDRegistryClient with the command
// line's registries trusted. Every registry client the CLI builds goes
// through it.
func newAWIDRegistryClient(httpClient *http.Client, txt awid.TXTResolver) *awid.RegistryClient {
	client := awid.NewAWIDRegistryClient(httpClient, txt)
	trustCommandLineRegistries(client.Resolver)
	if wd, err := os.Getwd(); err == nil {
		if home, err := identityHomeForDir(wd); err == nil {
			trustStoredRegistryOrigins(client.Resolver, wd, home.Root)
		}
	}
	return client
}

// newAWIDRegistryResolver is awid.NewRegistryResolver with the command
// line's registries trusted.
func newAWIDRegistryResolver(httpClient *http.Client, txt awid.TXTResolver) *awid.RegistryResolver {
	resolver := awid.NewRegistryResolver(httpClient, txt)
	trustCommandLineRegistries(resolver)
	return resolver
}

func matchingRegistryOrigin(registryURL, recorded string) string {
	if awid.SameRegistryOrigin(registryURL, recorded) {
		return registryURL
	}
	return ""
}

// operatorRegistryOrigin records provenance only when the persisted origin is
// the one the operator named. A discovered or returned URL carries no trust.
func operatorRegistryOrigin(registryURL, recorded string) string {
	if awid.SameRegistryOrigin(registryURL, recorded) || awid.SameRegistryOrigin(registryURL, os.Getenv("AWID_REGISTRY_URL")) {
		return registryURL
	}
	for _, origin := range commandLineRegistryOrigins() {
		if awid.SameRegistryOrigin(registryURL, origin) {
			return registryURL
		}
	}
	return ""
}

func saveWorktreeIdentityWithRegistryOrigin(path string, state *awconfig.WorktreeIdentity) error {
	state.RegistryOperatorOrigin = operatorRegistryOrigin(state.RegistryURL, state.RegistryOperatorOrigin)
	return awconfig.SaveWorktreeIdentityTo(path, state)
}

func trustRecordedRegistryOrigin(r *awid.RegistryResolver, registryURL, operatorOrigin string) {
	if r != nil && awid.SameRegistryOrigin(registryURL, operatorOrigin) {
		_ = r.TrustRegistryOrigin(operatorOrigin)
	}
}

func controllerRegistryOperatorOrigin(domain string, meta *awconfig.ControllerMeta) string {
	if !meta.LegacyRegistryOrigin {
		return matchingRegistryOrigin(meta.RegistryURL, meta.RegistryOperatorOrigin)
	}
	// Released implicit init stored the operator's URL in the reserved local
	// namespace controller record. Other legacy controller URLs could come
	// from discovery, so only the local controller's own record qualifies.
	if domain != implicitLocalDomain || meta.Domain != domain {
		return ""
	}
	key, err := awconfig.LoadControllerKey(domain)
	if err != nil || awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != meta.ControllerDID {
		return ""
	}
	return meta.RegistryURL
}

func trustControllerRegistryOrigin(r *awid.RegistryResolver, domain, origin string) {
	meta, err := awconfig.LoadControllerMeta(domain)
	if err == nil {
		trustRecordedRegistryOrigin(r, origin, controllerRegistryOperatorOrigin(domain, meta))
	}
}

// legacyLocalMembershipRegistryOrigin recovers implicit-local init's team
// route. An old teams.yaml entry alone cannot establish provenance, since a
// join wrote invite origins to the same field. Require this team's locally
// held controller key and the same origin as the local namespace controller.
func legacyLocalMembershipRegistryOrigin(membership *awconfig.TeamMembership, workingDir, identityHome string) string {
	if membership == nil || (membership.RegistryURL != "" && !membership.LegacyRegistryOrigin) {
		return ""
	}
	domain, name, err := awid.ParseTeamID(membership.TeamID)
	if err != nil || domain != implicitLocalDomain {
		return ""
	}
	meta, err := awconfig.LoadControllerMeta(domain)
	if err != nil {
		return ""
	}
	origin := controllerRegistryOperatorOrigin(domain, meta)
	if origin == "" || (membership.RegistryURL != "" && !awid.SameRegistryOrigin(membership.RegistryURL, origin)) {
		return ""
	}
	key, err := awconfig.LoadTeamKey(domain, name)
	if err != nil {
		return ""
	}
	cert, err := loadTeamCertificateAt(workingDir, identityHome, membership.TeamID)
	if err != nil || cert.Team != membership.TeamID || awid.NormalizeIdentityScope(cert.IdentityScope) != awid.IdentityModeLocal {
		return ""
	}
	if err := awid.CheckDecodedTeamCertificate(cert, awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))); err != nil {
		return ""
	}
	return origin
}

func trustStoredRegistryOrigins(r *awid.RegistryResolver, workingDir, identityHome string) {
	if identityHome == "" {
		identityHome = awconfig.WorktreeIdentityHome(workingDir)
	}
	if identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(identityHome, "identity.yaml")); err == nil {
		trustRecordedRegistryOrigin(r, identity.RegistryURL, identity.RegistryOperatorOrigin)
	}
	if state, err := awconfig.LoadTeamStateFromIdentityHome(identityHome); err == nil {
		for _, membership := range state.Memberships {
			trustRecordedRegistryOrigin(r, membership.RegistryURL, membership.RegistryOperatorOrigin)
		}
	}
}

func init() {
	identityCmd.AddCommand(&cobra.Command{
		Use:   "registry-trust <origin>",
		Short: "Trust an operator-selected registry recorded in this identity home",
		Long:  "Allow aw to reach an existing stored registry origin over private networks or HTTP. Only run this for an origin you operate or trust. The command does not change the selected registry.",
		Args:  cobra.ExactArgs(1),
		RunE:  runRegistryTrust,
	})
}

func runRegistryTrust(cmd *cobra.Command, args []string) error {
	origin, err := awid.CanonicalRegistryServerOrigin(args[0])
	if err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if err := markStoredRegistryOrigin(home, origin); err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Trusted registry %s\n", origin)
	return err
}

func markStoredRegistryOrigin(home awconfig.IdentityHome, origin string) error {
	path, err := awconfig.IdentityHomePath(home, "identity.yaml")
	if err != nil {
		return err
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if identity != nil && awid.SameRegistryOrigin(identity.RegistryURL, origin) {
		identity.RegistryOperatorOrigin = origin
		return awconfig.SaveWorktreeIdentityTo(path, identity)
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home.Root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if state != nil {
		matched := false
		for i := range state.Memberships {
			if awid.SameRegistryOrigin(state.Memberships[i].RegistryURL, origin) {
				state.Memberships[i].RegistryOperatorOrigin = origin
				matched = true
			}
		}
		if matched {
			return awconfig.SaveTeamStateToIdentityHome(home.Root, state)
		}
	}
	if identity != nil {
		if domain, _, ok := awconfig.CutIdentityAddress(identity.Address); ok {
			if marked, err := markControllerRegistryOrigin(domain, origin); marked || err != nil {
				return err
			}
		}
	}
	if state != nil {
		if membership := state.ActiveMembership(); membership != nil {
			if domain, _, err := awid.ParseTeamID(membership.TeamID); err == nil {
				if marked, err := markControllerRegistryOrigin(domain, origin); marked || err != nil {
					return err
				}
			}
		}
	}
	return usageError("registry %s is not recorded for the selected identity or team", origin)
}

func markControllerRegistryOrigin(domain, origin string) (bool, error) {
	meta, err := awconfig.LoadControllerMeta(domain)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !awid.SameRegistryOrigin(meta.RegistryURL, origin) {
		return false, nil
	}
	meta.RegistryOperatorOrigin = origin
	return true, awconfig.SaveControllerMeta(domain, meta)
}
