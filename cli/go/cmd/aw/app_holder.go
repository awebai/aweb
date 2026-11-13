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
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
	var unavailable *installationUnavailable
	switch {
	case errors.As(err, &unavailable) && unavailable.hinted:
		return "", withErrorCode(err.Error(), fmt.Errorf("%s's installation in team %s could not be read now; the service asks to retry after %d seconds: %w", a.Name, teamID, int64(unavailable.retryAfter/time.Second), err))
	case errors.As(err, &unavailable):
		return "", withErrorCode(err.Error(), fmt.Errorf("%s's installation in team %s could not be read now: %w", a.Name, teamID, err))
	case err != nil:
		return "", withErrorCode(err.Error(), fmt.Errorf("%s has no active installation in team %s", a.Name, teamID))
	}
	if current.Digest != a.Digest {
		return "", withErrorCode("installation_manifest_mismatch", fmt.Errorf("team %s's installation of %s is of manifest %s, not the %s installed here; update the app", teamID, a.Name, current.Digest, a.Digest))
	}
	return current.InstallationID, nil
}

// installationWithinBound is a.installation, waiting out each explicit
// Retry-After hint of an unavailable answer and reading again, while the wait
// ends before ctx's deadline. ctx carries the caller's bound; a hint that does
// not fit it, an unhinted or unusable answer, and every refusal end at once.
// Cancellation ends the wait.
func (a *holderApp) installationWithinBound(ctx context.Context, client *aweb.Client, teamID string) (string, error) {
	for {
		id, err := a.installation(ctx, client, teamID)
		var unavailable *installationUnavailable
		if err == nil || !errors.As(err, &unavailable) || !unavailable.hinted {
			return id, err
		}
		deadline, bounded := ctx.Deadline()
		if !bounded || !time.Now().Add(unavailable.retryAfter).Before(deadline) {
			return "", err
		}
		timer := time.NewTimer(unavailable.retryAfter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
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
	return app.holderOptions(cmd, roleName, "session")
}

// holderOptions are the handoff options for a holding of roleName. A human
// signs for itself. An agent certified directly by a human signs a session
// start for that human (handoff-wire 1a), sending its ID chain so the app
// can verify the edge; it never starts any other purpose for the human.
func (a *holderApp) holderOptions(cmd *cobra.Command, roleName, purpose string) (handoff.Options, error) {
	role, err := a.role(roleName)
	if err != nil {
		return handoff.Options{}, err
	}
	identity, err := resolveParticipationRequestIdentity()
	if err != nil {
		return handoff.Options{}, err
	}
	principal, chainHeader, err := holderFor(identity)
	if err != nil {
		return handoff.Options{}, err
	}
	if principal != identity.StableID {
		if purpose != "session" {
			return handoff.Options{}, withErrorCode("requester_not_holder", fmt.Errorf("only %s itself can start a %s handoff for its holding; an agent may start sessions only", principal, purpose))
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Requesting as %s for the holder %s.\n", identity.StableID, principal)
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
		Scope:   handoff.Scope{InstallationID: installationID, Role: role.Name, Principal: principal},
		Sign:    teamAuthSigner(identity, chainHeader),
		Open:    openBrowser,
		Notify:  cmd.ErrOrStderr(),
		HTTP:    &http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()},
	}, nil
}

// holderFor is the holder this identity starts handoffs for, and the
// X-AWID-ID-Chain value it sends when that holder is its parent. A human,
// or an identity with no installed chain, is its own holder.
func holderFor(identity *localSigningIdentity) (string, string, error) {
	if activeHuman != nil {
		return identity.StableID, "", nil
	}
	installed, err := awconfig.LoadInstalledIDChain(filepath.Dir(identity.SigningKeyPath))
	if err != nil {
		return "", "", err
	}
	if installed == nil {
		return identity.StableID, "", nil
	}
	certificates, _ := installed.Bundle["certificates"].([]any)
	if len(certificates) == 0 || idCertificateFields(certificates[len(certificates)-1])["kind"] != "agent" {
		return identity.StableID, "", nil
	}
	holder, err := directHumanParent(installed.Bundle)
	if err != nil {
		return "", "", err
	}
	return holder, installed.Header, nil
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
// as identity, following no redirect, with chainHeader as X-AWID-ID-Chain
// when it is set.
func teamAuthSigner(identity *localSigningIdentity, chainHeader string) handoff.Signer {
	return func(_ context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
		headers := http.Header{}
		headers.Set("Content-Type", "application/json")
		if chainHeader != "" {
			headers.Set("X-AWID-ID-Chain", chainHeader)
		}
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

// directHumanParent is the human an agent may prepare app session starts
// for: the direct parent of its own (leaf) ID certificate, when that parent's
// certificate is the one before it in the chain and its kind is human. The
// app verifies the chain and its current status; this only selects the
// holder and refuses a chain that can never qualify (handoff-wire 1a).
func directHumanParent(chain map[string]any) (string, error) {
	missing := withErrorCode("requester_missing", fmt.Errorf("this identity is not an agent certified directly by a human, so it cannot start a session for one; create one under the human with aw id create --human-parent <human>"))
	certificates, _ := chain["certificates"].([]any)
	if len(certificates) < 2 {
		return "", missing
	}
	leaf := idCertificateFields(certificates[len(certificates)-1])
	parent := idCertificateFields(certificates[len(certificates)-2])
	edge, _ := leaf["parent"].(map[string]any)
	if leaf["kind"] != "agent" || edge["kind"] != "identity" || parent["kind"] != "human" {
		return "", missing
	}
	holder, _ := edge["id"].(string)
	if holder == "" || parent["id"] != holder {
		return "", missing
	}
	return holder, nil
}

func idCertificateFields(signed any) map[string]any {
	envelope, _ := signed.(map[string]any)
	fields, _ := envelope["certificate"].(map[string]any)
	return fields
}
