package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// This is an explicitly selected native principal, never the destination or an
// ambient workspace/API-key credential. Its live org authority is checked by
// the service on every request.
type hostedOwnerAuthority struct {
	issuer      string
	apiURL      string
	did         string
	key         ed25519.PrivateKey
	home        string
	stableID    string
	registryURL string
}

func loadHostedOwnerAuthority(workingDir string, destination awconfig.IdentityHome, raw string) (*hostedOwnerAuthority, error) {
	if !filepath.IsAbs(strings.TrimSpace(raw)) {
		return nil, usageError("--owner-identity-home must name an absolute native credential directory")
	}
	home, err := awconfig.ResolveIdentityHome(workingDir, raw)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(home.Root) == filepath.Clean(destination.Root) {
		return nil, usageError("owner and destination credential roots must differ")
	}
	ownerInfo, err := os.Stat(home.Root)
	if err != nil {
		return nil, err
	}
	if !ownerInfo.IsDir() {
		return nil, usageError("owner credential root must be a directory")
	}
	if targetInfo, err := os.Stat(destination.Root); err == nil && os.SameFile(ownerInfo, targetInfo) {
		return nil, usageError("owner and destination credential roots must differ")
	}
	if awconfig.IsGrantHome(home.Root) {
		return nil, usageError("owner authority requires its native signing key; grant roots cannot authorize creation")
	}
	keyPath, err := awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return nil, err
	}
	key, err := awid.LoadSigningKey(keyPath)
	if err != nil {
		return nil, err
	}
	did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	identityPath, err := awconfig.IdentityHomePath(home, "identity.yaml")
	if err != nil {
		return nil, err
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && identity.DID != did {
		return nil, usageError("owner identity does not match its native signing key")
	}
	bindingPath, err := awconfig.IdentityHomePath(home, "workspace.yaml")
	if err != nil {
		return nil, err
	}
	binding, err := awconfig.LoadWorktreeWorkspaceFrom(bindingPath)
	if err != nil {
		return nil, err
	}
	base := strings.TrimSpace(binding.AwebURL)
	parsed, err := url.Parse(base)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, usageError("owner root requires its own valid service workspace binding")
	}
	stableID, registryURL := "", ""
	if identity != nil {
		stableID, registryURL = identity.StableID, identity.RegistryURL
	}
	return &hostedOwnerAuthority{home: home.Root, stableID: stableID, registryURL: registryURL, issuer: parsed.Scheme + "://" + parsed.Host, apiURL: base, did: did, key: key}, nil
}

func postHostedOwnerIdentity(ctx context.Context, owner *hostedOwnerAuthority, input any, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, owner.issuer+cliIdentityCreatePath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	headers, err := awid.DIDKeyRequestHeadersForAudience(req.Method, req.URL.Path, owner.issuer, body, owner.key)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return doCLIJSON(req, output, owner.issuer, true)
}
