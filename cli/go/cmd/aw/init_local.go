package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

const implicitLocalDomain = "local"
const implicitLocalTeamName = "default"

type implicitLocalInitRequest struct {
	WorkingDir  string
	AwebURL     string
	RegistryURL string
	Alias       string
	Role        string
	HumanName   string
	AgentType   string
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
		return connectOutput{}, usageError("--alias is required when aw init targets a localhost awid registry")
	}
	if err := ensureConnectTargetClean(req.WorkingDir); err != nil {
		return connectOutput{}, err
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ensureStandaloneRegistryRegistration(ctx, registry, prepared.Plan, prepared.ControllerKey, prepared.IdentityKey); err != nil {
		return connectOutput{}, err
	}

	team, err := bootstrapLocalTeamMemberWithLifetime(
		ctx,
		registry,
		prepared.Plan.RegistryURL,
		prepared.Plan.Domain,
		implicitLocalTeamName,
		"",
		prepared.ControllerKey,
		prepared.IdentityKey,
		prepared.Plan.DIDAW,
		prepared.Plan.Address,
		alias,
		awid.LifetimeEphemeral,
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
