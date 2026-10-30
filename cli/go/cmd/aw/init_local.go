package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
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

// localNamespaceOnRemoteRegistry refuses --new-team against a registry that
// is not on this machine: the self-hosted namespace is created only there.
func localNamespaceOnRemoteRegistry(registryURL string) error {
	return usageError("--new-team without --byod creates the self-hosted namespace %q, which is created only against an awid registry on this machine; %s is not on this machine. "+
		"The first machine to create %q on a registry owns it with its controller key. "+
		"To add this machine to a team there, run `aw team invite` on a member's machine and `aw team join <token>` here; "+
		"to create a namespace of your own, run `aw init --new-team --byod --domain <a domain you control>`",
		implicitLocalDomain, registryURL, implicitLocalDomain)
}

// localNamespaceHeldElsewhere refuses before this machine mints a controller
// key for a namespace another machine's controller already holds.
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
	return usageError("the self-hosted namespace %q on %s is owned by controller %s, created on another machine. "+
		"To add this machine to a team there, run `aw team invite` on a member's machine and `aw team join <token>` here",
		implicitLocalDomain, registryURL, strings.TrimSpace(namespace.ControllerDID))
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
