package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const implicitLocalDomain = "local"
const implicitLocalTeamName = "default"

type implicitLocalInitRequest struct {
	WorkingDir  string
	AwebURL     string
	RegistryURL string
	Alias       string
	TeamName    string
	Role        string
	HumanName   string
	AgentType   string
}

func implicitLocalTeamNameValue(value string) string {
	if team := strings.TrimSpace(value); team != "" {
		return strings.ToLower(team)
	}
	return implicitLocalTeamName
}

// localTeamAdvice is what to do instead when aw init cannot create a local
// team: join a team there, or create one under a domain you control.
const localTeamAdvice = "To join a team there, ask a member to run `aw team invite` and run the `aw team join` command it prints here. " +
	"To create a team of your own, use a domain you control: `aw init --new-team --byod --domain <a domain you control>`."

// localNamespaceOnRemoteRegistry refuses --new-team against a registry URL
// that is not loopback: the self-hosted namespace is created only through one.
func localNamespaceOnRemoteRegistry(registryURL string) error {
	return usageError("aw init --new-team creates a local team only on an awid registry at localhost, and %s is not one. %s", registryURL, localTeamAdvice)
}

// localNamespaceHeldElsewhere refuses before this home mints a controller key
// for a namespace that a controller key it does not hold already controls.
func localNamespaceHeldElsewhere(ctx context.Context, registry *awid.RegistryClient, registryURL string) error {
	namespace, _, err := registry.GetNamespaceAt(ctx, registryURL, implicitLocalDomain)
	if code, ok := registryStatusCode(err); ok && code == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if exists, err := awconfig.ControllerKeyExists(implicitLocalDomain); err != nil {
		return err
	} else if exists {
		key, err := awconfig.LoadControllerKey(implicitLocalDomain)
		if err != nil {
			return err
		}
		if awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) == strings.TrimSpace(namespace.ControllerDID) {
			return nil
		}
	}
	return usageError("The local namespace on %s was set up with a key this home does not hold, so aw init cannot create a team in it. %s", registryURL, localTeamAdvice)
}

// initTeamFlagApplies reports whether this init can reach the local
// --new-team path, the only one that reads --team. The paths runInit takes
// before it (workspace team, --join-from, admission, AWEB_API_KEY, an
// existing certificate or workspace) would ignore the flag.
func initTeamFlagApplies() bool {
	if !initNewTeam || initBYOD || initGlobal || strings.TrimSpace(initUsername) != "" || strings.TrimSpace(initDomain) != "" {
		return false
	}
	if initWorkspaceTeam || strings.TrimSpace(initJoinFrom) != "" || strings.TrimSpace(initAdmissionTeamID) != "" || resolveInitAPIKey() != "" {
		return false
	}
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	if hasCertificateForInit(wd) {
		return false
	}
	missing, err := initWorkspaceMissing(wd)
	return err == nil && missing
}

// initTeamFlagUsageError says where --team applies.
func initTeamFlagUsageError() error {
	return usageError("--team names the team that aw init --new-team creates on a local (localhost) awid registry, in a folder with no aw workspace or certificate; it does not apply without --new-team, with --byod, --domain, --global, --username, --join-from or --workspace-team, or with AWEB_API_KEY set")
}

// localTeamAlreadyExists refuses --new-team for a local team that is already
// registered, instead of adding this workspace to it as if it were new.
func localTeamAlreadyExists(ctx context.Context, registry *awid.RegistryClient, registryURL, teamName string) error {
	_, err := registry.GetTeam(ctx, registryURL, implicitLocalDomain, teamName, nil)
	if code, ok := registryStatusCode(err); ok && code == http.StatusNotFound {
		return nil
	}
	// A private team refuses this unsigned read with team_private, which
	// AWID answers only for a team that exists.
	if err != nil && !awid.IsTeamPrivateError(err) {
		return err
	}
	return usageError("Team %s:%s already exists. To join it, ask a member for an invite. To create another team, pass --team <name>.", teamName, implicitLocalDomain)
}

// recordLocalControllerRegistry records the registry where this home's
// `local` namespace now lives, so invites carry it after the stack moves.
func recordLocalControllerRegistry(registryURL string) error {
	meta, err := awconfig.LoadControllerMeta(implicitLocalDomain)
	if err != nil {
		return err
	}
	if strings.TrimSpace(meta.RegistryURL) == strings.TrimSpace(registryURL) {
		return nil
	}
	meta.RegistryURL = strings.TrimSpace(registryURL)
	return awconfig.SaveControllerMeta(implicitLocalDomain, meta)
}

func runImplicitLocalInit(req implicitLocalInitRequest) (connectOutput, error) {
	if strings.TrimSpace(req.WorkingDir) == "" {
		return connectOutput{}, fmt.Errorf("working directory is required")
	}
	if strings.TrimSpace(req.AwebURL) == "" {
		return connectOutput{}, fmt.Errorf("aweb URL is required")
	}
	if strings.TrimSpace(req.RegistryURL) == "" {
		return connectOutput{}, fmt.Errorf("awid registry URL is required")
	}
	alias := strings.TrimSpace(req.Alias)
	if alias == "" {
		return connectOutput{}, usageError("--name is required when aw init targets a localhost awid registry")
	}
	if err := ensureConnectTargetClean(req.WorkingDir); err != nil {
		return connectOutput{}, err
	}
	{
		registry, err := newConfiguredRegistryClient(nil, "")
		if err != nil {
			return connectOutput{}, err
		}
		ctx, cancel := commandAPIContext(nil)
		err = localNamespaceHeldElsewhere(ctx, registry, req.RegistryURL)
		if err == nil {
			err = localTeamAlreadyExists(ctx, registry, req.RegistryURL, implicitLocalTeamNameValue(req.TeamName))
		}
		cancel()
		if err != nil {
			return connectOutput{}, err
		}
	}

	prepared, err := prepareIDCreatePlan(req.WorkingDir, idCreateOptions{
		Name:                     alias,
		Domain:                   implicitLocalDomain,
		RegistryURL:              req.RegistryURL,
		AllowReservedLocalDomain: true,
		Now:                      time.Now,
	})
	if err != nil {
		return connectOutput{}, err
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return connectOutput{}, err
	}
	if err := registry.SetFallbackRegistryURL(prepared.Plan.RegistryURL); err != nil {
		return connectOutput{}, fmt.Errorf("invalid planned registry URL: %w", err)
	}

	ctx, cancel := commandAPIContext(nil)
	defer cancel()

	if err := ensureStandaloneNamespace(ctx, registry, prepared.Plan, prepared.ControllerKey); err != nil {
		return connectOutput{}, err
	}
	if err := recordLocalControllerRegistry(prepared.Plan.RegistryURL); err != nil {
		return connectOutput{}, err
	}

	team, err := bootstrapLocalTeamMemberWithScope(
		ctx,
		registry,
		prepared.Plan.RegistryURL,
		prepared.Plan.Domain,
		implicitLocalTeamNameValue(req.TeamName),
		"",
		prepared.ControllerKey,
		prepared.IdentityKey,
		"",
		"",
		alias,
		awid.IdentityModeLocal,
	)
	if err != nil {
		return connectOutput{}, err
	}

	if err := persistLocalSigningKeyAndCertificate(req.WorkingDir, prepared.IdentityKey, team.Certificate); err != nil {
		return connectOutput{}, err
	}

	return initCertificateConnectWithOptions(req.WorkingDir, req.AwebURL, certificateConnectOptions{
		Role:      strings.TrimSpace(req.Role),
		HumanName: strings.TrimSpace(req.HumanName),
		AgentType: strings.TrimSpace(req.AgentType),
	})
}
