package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
)

type clientRecordingPolicy uint8

const (
	clientDetached clientRecordingPolicy = iota
	clientForCommand
)

type clientRequest struct {
	WorkingDir string
	Home       awconfig.IdentityHome
	TeamID     string
	ServerName string
	Selection  *awconfig.Selection
	BaseURL    baseURLResolver
	Record     clientRecordingPolicy
}

// newClient applies docs/cli-identity-selection.md's selected-principal rule.
// Inputs are captured by the command boundary; this owner never reads selection
// flags or changes command state for a detached client.
func newClient(ctx context.Context, request clientRequest) (*aweb.Client, *awconfig.Selection, error) {
	if strings.TrimSpace(request.WorkingDir) == "" {
		return nil, nil, errors.New("client request requires a working directory")
	}
	if request.BaseURL == nil {
		return nil, nil, errors.New("client request requires a base URL resolver")
	}
	var client *aweb.Client
	var selection *awconfig.Selection
	var err error
	if request.Selection == nil && awconfig.IsGrantHome(request.Home.Root) {
		client, selection, err = buildGrantClientSelectionForTeam(ctx, request.WorkingDir, request.Home, request.TeamID, request.BaseURL)
	} else {
		selection = request.Selection
		if selection == nil {
			selection, err = selectClientWorkspace(request)
		}
		if err == nil {
			client, selection, err = buildSelectedCertificateClient(ctx, request, selection)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if request.Record == clientForCommand {
		lastClient = client
	}
	return client, selection, nil
}

func selectClientWorkspace(request clientRequest) (*awconfig.Selection, error) {
	return awconfig.ResolveWorkspace(awconfig.ResolveOptions{
		WorkingDir:           request.WorkingDir,
		IdentityHome:         request.Home.Root,
		ExternalIdentityHome: request.Home.External(),
		ServerName:           request.ServerName,
		TeamIDOverride:       strings.TrimSpace(request.TeamID),
		AllowEnvOverrides:    true,
	})
}

func buildSelectedCertificateClient(ctx context.Context, request clientRequest, sel *awconfig.Selection) (*aweb.Client, *awconfig.Selection, error) {
	if sel == nil {
		return nil, nil, errors.New("client request requires a workspace selection")
	}
	if strings.TrimSpace(sel.WorkspacePath) == "" {
		if recovery, ok := workspaceConnectRecoveryCommand(request.WorkingDir, request.Home.Root); ok {
			return nil, nil, usageError("current identity is not connected to an aweb workspace; run `%s`", recovery)
		}
	}
	if err := checkIdentityMismatchAtIdentityHome(request.WorkingDir, request.Home.Root, sel); err != nil {
		return nil, nil, err
	}

	baseURL, err := request.BaseURL(ctx, sel.BaseURL)
	if err != nil {
		return nil, nil, err
	}
	sel.BaseURL = baseURL

	c, err := resolveCertificateClient(sel, baseURL)
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return nil, nil, errors.New("current workspace is not certificate-authenticated; accept a team invite and run `aw init` here")
	}
	if err := configureResolvedClient(c, sel, baseURL); err != nil {
		return nil, nil, err
	}
	home := strings.TrimSpace(sel.IdentityHome)
	if home == "" {
		home = filepath.Dir(sel.SigningKey)
	}
	selected := *sel
	c.SetTeamCertificateRefresh(func(ctx context.Context) (string, error) {
		return refreshOwnTeamCertificate(ctx, &selected, home)
	})
	return c, sel, nil
}
