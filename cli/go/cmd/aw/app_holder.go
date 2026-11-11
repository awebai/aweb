package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// holderApp is an installed app that declares owner-designated roles: its
// pinned manifest and the two origins that manifest pins.
type holderApp struct {
	Name     string
	AppID    string
	Digest   string
	Origins  handoff.Origins
	Resolved *appmanifest.Resolved
}

// installedHolderApp reads the app installed under name from this machine's
// plugin directory. Only the pinned manifest names the origins; nothing is
// taken from a server response.
func installedHolderApp(name string) (*holderApp, error) {
	dir, err := pluginDir()
	if err != nil {
		return nil, err
	}
	data, err := readFileBounded(manifestPluginManifestPath(dir, name), maxManifestBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, withErrorCode("app_not_installed", fmt.Errorf("no app %q is installed; install it with aw plugin install", name))
	}
	if err != nil {
		return nil, err
	}
	resolved, err := appmanifest.Load(data, reservedRootCommandNames())
	if err != nil {
		return nil, fmt.Errorf("installed manifest of %s: %w", name, manifestError(err))
	}
	if resolved.OwnerActs == nil {
		return nil, withErrorCode("owner_acts_undeclared", fmt.Errorf("%s declares no roles held by a team's humans", name))
	}
	provenance, err := loadPluginProvenance(manifestPluginProvenancePath(dir, name))
	if err != nil {
		return nil, err
	}
	if provenance == nil || strings.TrimSpace(provenance.Digest) == "" {
		return nil, withErrorCode("app_not_installed", fmt.Errorf("%s has no recorded install; reinstall it with aw plugin install", name))
	}
	return &holderApp{
		Name: name, AppID: resolved.Manifest.App.ID, Digest: provenance.Digest,
		Origins:  handoff.Origins{App: resolved.Manifest.App.Origin, Human: resolved.OwnerActs.Origin},
		Resolved: resolved,
	}, nil
}

// role is the owner-designated role the pinned manifest declares under name.
func (a *holderApp) role(name string) (appmanifest.OwnerActRole, error) {
	for _, role := range a.Resolved.OwnerActs.Roles {
		if role.Name == strings.TrimSpace(name) {
			return role, nil
		}
	}
	return appmanifest.OwnerActRole{}, withErrorCode("role_not_declared", fmt.Errorf("%s declares no role %q", a.Name, name))
}

// installation is the app's active installation in the selected team, which
// must be of the manifest this machine pinned.
func (a *holderApp) installation(ctx context.Context, client *aweb.Client, teamID string) (string, error) {
	current, err := activeInstallation(ctx, client, teamID, a.AppID)
	if err != nil {
		return "", withErrorCode(err.Error(), fmt.Errorf("%s has no active installation in team %s", a.Name, teamID))
	}
	if current.Digest != a.Digest {
		return "", withErrorCode("installation_manifest_mismatch", fmt.Errorf("team %s's installation of %s is of manifest %s, not the %s installed here; update the app", teamID, a.Name, current.Digest, a.Digest))
	}
	return current.InstallationID, nil
}

// holderSessionOptions are the options of a session handoff for roleName on
// the installed app appName, as the signing identity of this command
// (--human, or the identity home). It opens the local browser and reports on
// stderr.
func holderSessionOptions(cmd *cobra.Command, appName, roleName string) (handoff.Options, error) {
	app, err := installedHolderApp(appName)
	if err != nil {
		return handoff.Options{}, err
	}
	return app.holderOptions(cmd, roleName)
}

// holderOptions are the handoff options for a holding of roleName by this
// command's signing identity.
func (a *holderApp) holderOptions(cmd *cobra.Command, roleName string) (handoff.Options, error) {
	role, err := a.role(roleName)
	if err != nil {
		return handoff.Options{}, err
	}
	identity, err := resolveParticipationRequestIdentity()
	if err != nil {
		return handoff.Options{}, err
	}
	client, selection, err := participationClient()
	if err != nil {
		return handoff.Options{}, err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	installationID, err := a.installation(ctx, client, selection.TeamID)
	if err != nil {
		return handoff.Options{}, err
	}
	return handoff.Options{
		Origins: a.Origins,
		Scope:   handoff.Scope{InstallationID: installationID, Role: role.Name, Principal: identity.StableID},
		Sign:    teamAuthSigner(identity),
		Open:    openBrowser,
		Notify:  cmd.ErrOrStderr(),
		HTTP:    &http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()},
	}, nil
}

// participationClient is the aweb client of the team this command acts in,
// as --human or as the identity home.
func participationClient() (*aweb.Client, *awconfig.Selection, error) {
	if activeHuman != nil {
		return activeHuman.client(teamFlag, "")
	}
	return resolveClientSelection()
}

// teamAuthSigner sends a request to an app origin signed with team-auth v2
// as identity, following no redirect.
func teamAuthSigner(identity *localSigningIdentity) handoff.Signer {
	return func(_ context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
		headers := http.Header{}
		headers.Set("Content-Type", "application/json")
		result, err := executeSignedIDRequest(method, target, identity, body, headers, map[string]any{}, true)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: result.Status, Header: result.Header, Body: io.NopCloser(bytes.NewReader(result.Body))}, nil
	}
}

// openBrowser opens target in the platform's browser.
func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go command.Wait() //nolint:errcheck // the opener's exit says nothing about the page
	return nil
}
