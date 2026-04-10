package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/joho/godotenv"
)

// DefaultAwebURL is the public aweb instance used when no aweb URL is
// configured via flags, environment, or local config.
const DefaultAwebURL = "https://app.aweb.ai"

func loadDotenvBestEffort() {
	// Best effort: load from current working directory.
	_ = godotenv.Load()
	_ = godotenv.Overload(".env.aweb")
}

// lastClient holds the most recently created client, used to check
// the X-Latest-Client-Version header after command execution.
var lastClient *aweb.Client

type identityMismatchError struct {
	ContextPath    string
	WorkspacePath  string
	ResolvedAlias  string
	WorkspaceAlias string
}

func (e *identityMismatchError) Error() string {
	ctxPath := e.ContextPath
	if strings.TrimSpace(ctxPath) == "" {
		ctxPath = "(resolved from config)"
	}
	wsPath := e.WorkspacePath
	if strings.TrimSpace(wsPath) == "" {
		wsPath = "(unknown)"
	}
	return fmt.Sprintf("identity mismatch: .aw/context at %s resolves to %q, but .aw/workspace.yaml at %s says %q. Run 'aw init' in this worktree to fix.",
		ctxPath, strings.TrimSpace(e.ResolvedAlias), wsPath, strings.TrimSpace(e.WorkspaceAlias))
}

func isIdentityMismatchError(err error) bool {
	var mismatch *identityMismatchError
	return errors.As(err, &mismatch)
}

func resolveClientSelection() (*aweb.Client, *awconfig.Selection, error) {
	wd, _ := os.Getwd()
	return resolveClientSelectionForDir(wd)
}

func resolveSelectionForDir(workingDir string) (*awconfig.Selection, error) {
	sel, err := awconfig.ResolveWorkspace(awconfig.ResolveOptions{
		ServerName:        serverFlag,
		TeamIDOverride:    strings.TrimSpace(teamFlag),
		WorkingDir:        workingDir,
		AllowEnvOverrides: true,
	})
	if err != nil {
		return nil, err
	}
	return sel, nil
}

func resolveIdentity() (*awconfig.ResolvedIdentity, error) {
	wd, _ := os.Getwd()
	return awconfig.ResolveIdentity(wd)
}

func resolveClientSelectionForDir(workingDir string) (*aweb.Client, *awconfig.Selection, error) {
	sel, err := resolveSelectionForDir(workingDir)
	if err != nil {
		return nil, nil, err
	}

	if err := checkIdentityMismatch(workingDir, sel); err != nil {
		return nil, nil, err
	}

	baseURL, err := resolveAuthenticatedBaseURL(sel.BaseURL)
	if err != nil {
		return nil, nil, err
	}
	sel.BaseURL = baseURL

	c, err := resolveCertificateClient(workingDir, baseURL, strings.TrimSpace(sel.TeamID))
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return nil, nil, errors.New("current workspace is not certificate-authenticated; accept a team invite and run `aw init` here")
	}
	if err := configureResolvedClient(c, sel, baseURL); err != nil {
		return nil, nil, err
	}

	lastClient = c
	return c, sel, nil
}

func resolveIdentityMessagingClientSelection() (*aweb.Client, *awconfig.Selection, error) {
	wd, _ := os.Getwd()
	return resolveIdentityMessagingClientSelectionForDir(wd)
}

func resolveIdentityMessagingClientSelectionForDir(workingDir string) (*aweb.Client, *awconfig.Selection, error) {
	sel, err := resolveSelectionForDir(workingDir)
	if err != nil {
		return nil, nil, err
	}

	if err := checkIdentityMismatch(workingDir, sel); err != nil {
		return nil, nil, err
	}

	baseURL, err := resolveAuthenticatedBaseURL(sel.BaseURL)
	if err != nil {
		return nil, nil, err
	}
	sel.BaseURL = baseURL

	identity, err := awconfig.ResolveIdentity(workingDir)
	if err != nil {
		return nil, nil, errors.New("current workspace has no local identity; run `aw init` here first")
	}
	signingKey, err := awid.LoadSigningKey(identity.SigningKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load signing key: %w", err)
	}
	rawClient, err := awid.NewWithIdentity(baseURL, signingKey, identity.DID)
	if err != nil {
		return nil, nil, err
	}
	c := &aweb.Client{Client: rawClient}
	if strings.TrimSpace(sel.StableID) == "" {
		sel.StableID = strings.TrimSpace(identity.StableID)
	}
	if strings.TrimSpace(sel.Address) == "" {
		sel.Address = strings.TrimSpace(identity.Address)
	}
	if err := configureResolvedClient(c, sel, baseURL); err != nil {
		return nil, nil, err
	}

	lastClient = c
	return c, sel, nil
}

// resolveCertificateClient attempts to create a certificate-authenticated client.
// Returns (nil, nil) if no team certificate exists. Returns an error only if the
// certificate exists but is invalid.
func resolveCertificateClient(workingDir, baseURL, teamID string) (*aweb.Client, error) {
	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir)
	if err != nil {
		return nil, nil
	}
	selectedMembership := workspace.Membership(teamID)
	if selectedMembership == nil {
		if strings.TrimSpace(teamID) != "" {
			return nil, fmt.Errorf("team %q is not present in workspace memberships; available: %s", teamID, strings.Join(workspace.AvailableTeamIDs(), ", "))
		}
		return nil, fmt.Errorf("workspace is missing active_team membership")
	}
	certPath := filepath.Join(workingDir, ".aw", filepath.FromSlash(strings.TrimSpace(selectedMembership.CertPath)))
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		return nil, fmt.Errorf("load team certificate for %s: %w", selectedMembership.TeamID, err)
	}
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("team certificate found but signing key missing: %w", err)
	}
	return aweb.NewWithCertificate(baseURL, signingKey, cert)
}

func configureResolvedClient(c *aweb.Client, sel *awconfig.Selection, baseURL string) error {
	if c == nil || sel == nil {
		return nil
	}
	c.SetAddress(selectionAddress(sel))
	if sel.StableID != "" {
		c.SetStableID(sel.StableID)
	}

	pinPath, err := awconfig.DefaultKnownAgentsPath()
	if err != nil {
		return err
	}
	ps, err := awid.LoadPinStore(pinPath)
	if err != nil {
		debugLog("load pin store: %v", err)
		ps = awid.NewPinStore()
	}
	c.SetPinStore(ps, pinPath)
	registry, err := newConfiguredRegistryResolver(c.Client.HTTPClient(), baseURL)
	if err != nil {
		return err
	}
	c.SetResolver(&awid.ChainResolver{
		DIDKey:   &awid.DIDKeyResolver{},
		Registry: registry,
		Pin:      &awid.PinResolver{Store: ps},
	})

	configureBaseURLFallback(c, sel, baseURL)
	return nil
}

func resolveClient() (*aweb.Client, error) {
	c, _, err := resolveClientSelection()
	return c, err
}

func cleanBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty base url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid base url %q", raw)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func probeAwebBaseURL(ctx context.Context, baseURL string) (bool, error) {
	// Stable across our servers: exists (POST) on /v1/agents/heartbeat.
	// We use GET to avoid side effects; success is any non-404 response
	// with a non-HTML content type (to distinguish a web app from an API).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/agents/heartbeat", nil)
	if err != nil {
		return false, err
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	debugLog("probe aweb base url: %s -> %d", baseURL, resp.StatusCode)
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		debugLog("probe aweb base url: %s rejected (HTML response)", baseURL)
		return false, nil
	}
	return true, nil
}

func resolveWorkingBaseURL(raw string) (string, error) {
	return resolveWorkingBaseURLContext(context.Background(), raw)
}

func resolveWorkingBaseURLContext(ctx context.Context, raw string) (string, error) {
	base, err := cleanBaseURL(raw)
	if err != nil {
		return "", err
	}

	candidates := make([]string, 0, 4)
	add := func(v string) {
		v = strings.TrimSuffix(strings.TrimSpace(v), "/")
		if v == "" {
			return
		}
		for _, existing := range candidates {
			if existing == v {
				return
			}
		}
		candidates = append(candidates, v)
	}

	add(base)
	if strings.HasSuffix(base, "/v1") {
		add(strings.TrimSuffix(base, "/v1"))
	}
	if strings.HasSuffix(base, "/api/v1") {
		add(strings.TrimSuffix(base, "/v1"))
	}
	if strings.HasSuffix(base, "/api") {
		add(strings.TrimSuffix(base, "/api"))
	}
	if !strings.HasSuffix(base, "/api") {
		add(base + "/api")
	}

	var lastErr error
	for _, cand := range candidates {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		debugLog("resolve base url: probing %s", cand)
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ok, err := probeAwebBaseURL(probeCtx, cand)
		cancel()
		if err != nil {
			debugLog("resolve base url: probe %s failed: %v", cand, err)
			lastErr = err
			continue
		}
		if ok {
			debugLog("resolve base url: selected %s", cand)
			return cand, nil
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("no aweb API detected at %q (tried %v): %w", raw, candidates, lastErr)
	}
	return "", fmt.Errorf("no aweb API detected at %q (tried %v)", raw, candidates)
}

func resolveAuthenticatedBaseURL(raw string) (string, error) {
	if envBaseURL := strings.TrimSpace(os.Getenv("AWEB_URL")); envBaseURL != "" {
		return resolveWorkingBaseURL(envBaseURL)
	}
	return cleanBaseURL(raw)
}

func configureBaseURLFallback(c *aweb.Client, sel *awconfig.Selection, baseURL string) {
	if c == nil || sel == nil || strings.TrimSpace(sel.ServerName) == "" {
		return
	}
	if strings.TrimSpace(os.Getenv("AWEB_URL")) != "" {
		return
	}
	state := &baseURLFallbackState{
		configuredBaseURL: strings.TrimSuffix(baseURL, "/"),
		currentBaseURL:    strings.TrimSuffix(baseURL, "/"),
		persist: func(resolved string) {
			if err := persistResolvedAwebURL(sel.WorkspacePath, resolved); err != nil {
				debugLog("persist resolved base URL for %s: %v", sel.WorkspacePath, err)
			}
		},
	}
	c.SetHTTPClient(&http.Client{
		Timeout: awid.DefaultTimeout,
		Transport: &baseURLFallbackTransport{
			base:  http.DefaultTransport,
			state: state,
		},
	})
	c.SetSSEClient(&http.Client{
		Transport: &baseURLFallbackTransport{
			base:  http.DefaultTransport,
			state: state,
		},
	})
}

func newConfiguredRegistryResolver(httpClient *http.Client, baseURL string) (*awid.RegistryResolver, error) {
	registry := awid.NewRegistryResolver(httpClient, nil)
	if err := configureEmbeddedRegistryBaseURL(baseURL, registry.SetFallbackRegistryURL); err != nil {
		return nil, err
	}
	return registry, nil
}

func newConfiguredRegistryClient(httpClient *http.Client, baseURL string) (*awid.RegistryClient, error) {
	client := awid.NewAWIDRegistryClient(httpClient, nil)
	if err := configureEmbeddedRegistryBaseURL(baseURL, client.SetFallbackRegistryURL); err != nil {
		return nil, err
	}
	return client, nil
}

func loadOptionalWorktreeSigningKey(workingDir string) (ed25519.PrivateKey, error) {
	workingDir = strings.TrimSpace(workingDir)
	if workingDir == "" {
		var err error
		workingDir, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	}
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return signingKey, nil
}

func configureEmbeddedRegistryBaseURL(baseURL string, setFallback func(string) error) error {
	registryValue := strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL"))
	if registryValue == "" {
		return nil
	}
	if !strings.EqualFold(registryValue, "local") {
		if err := setFallback(registryValue); err != nil {
			return fmt.Errorf("invalid AWID_REGISTRY_URL: %w", err)
		}
		return nil
	}
	if err := setFallback(baseURL); err != nil {
		return fmt.Errorf("invalid embedded registry base URL: %w", err)
	}
	return nil
}

func persistResolvedAwebURL(workspacePath, baseURL string) error {
	workspacePath = strings.TrimSpace(workspacePath)
	baseURL = strings.TrimSpace(baseURL)
	if workspacePath == "" || baseURL == "" {
		return nil
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(workspace.AwebURL) == baseURL {
		return nil
	}
	workspace.AwebURL = baseURL
	return awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace)
}

type baseURLFallbackState struct {
	configuredBaseURL string
	currentBaseURL    string
	mu                sync.RWMutex
	persist           func(string)
}

type baseURLFallbackTransport struct {
	base  http.RoundTripper
	state *baseURLFallbackState
}

func (t *baseURLFallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.state == nil {
		return base.RoundTrip(req)
	}

	current := t.state.current()
	prepared, err := t.requestForBase(req, current)
	if err != nil {
		return nil, err
	}
	resp, err := base.RoundTrip(prepared)
	if !shouldRetryBaseURLRequest(resp, err) {
		return resp, err
	}

	debugLog("baseurl fallback: triggering for %s %s", req.Method, req.URL.String())
	fresh, changed := t.state.refresh(req.Context(), current)
	if !changed {
		debugLog("baseurl fallback: no recovered base URL for %s", current)
		return resp, err
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	retried, err := t.requestForBase(req, fresh)
	if err != nil {
		return nil, err
	}
	resp, err = base.RoundTrip(retried)
	if err == nil && t.state.persist != nil {
		t.state.persist(fresh)
	}
	debugLog("baseurl fallback: retried via %s", fresh)
	return resp, err
}

func (s *baseURLFallbackState) current() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentBaseURL
}

func (s *baseURLFallbackState) refresh(ctx context.Context, stale string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentBaseURL != stale {
		return s.currentBaseURL, s.currentBaseURL != stale
	}
	fresh, err := resolveWorkingBaseURLContext(ctx, stale)
	if err != nil || fresh == "" || fresh == stale {
		return stale, false
	}
	s.currentBaseURL = fresh
	return fresh, true
}

func (t *baseURLFallbackTransport) requestForBase(req *http.Request, baseURL string) (*http.Request, error) {
	if t.state == nil || strings.TrimSuffix(baseURL, "/") == t.state.configuredBaseURL {
		return req, nil
	}

	clone := req.Clone(req.Context())
	if req.Body != nil {
		if req.GetBody == nil {
			return nil, fmt.Errorf("request body cannot be retried for base URL fallback")
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	rebased, err := rebaseRequestURL(req.URL, t.state.configuredBaseURL, baseURL)
	if err != nil {
		return nil, err
	}
	clone.URL = rebased
	clone.Host = rebased.Host
	return clone, nil
}

// shouldRetryBaseURLRequest decides whether the base-URL fallback transport
// should retry against the alternative URL. The 404 check handles misconfigured
// base URLs (e.g. user stored /api in the URL and the path doubled). This does
// mean legitimate API 404s (agent not found, task not found) also trigger a
// retry, adding one extra round-trip before the real 404 propagates.
func shouldRetryBaseURLRequest(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	return resp != nil && resp.StatusCode == http.StatusNotFound
}

func rebaseRequestURL(reqURL *url.URL, fromBaseURL, toBaseURL string) (*url.URL, error) {
	from, err := url.Parse(fromBaseURL)
	if err != nil {
		return nil, err
	}
	to, err := url.Parse(toBaseURL)
	if err != nil {
		return nil, err
	}

	fromPath := strings.TrimSuffix(from.Path, "/")
	toPath := strings.TrimSuffix(to.Path, "/")
	relPath := reqURL.Path
	if fromPath != "" && strings.HasPrefix(relPath, fromPath) {
		relPath = strings.TrimPrefix(relPath, fromPath)
		if relPath == "" {
			relPath = "/"
		}
	}

	rebased := *reqURL
	rebased.Scheme = to.Scheme
	rebased.Host = to.Host
	rebased.Path = joinURLPath(toPath, relPath)
	rebased.RawPath = ""
	return &rebased, nil
}

func joinURLPath(basePath, relPath string) string {
	basePath = strings.TrimSuffix(basePath, "/")
	if relPath == "" {
		relPath = "/"
	}
	if !strings.HasPrefix(relPath, "/") {
		relPath = "/" + relPath
	}
	if basePath == "" {
		return relPath
	}
	return basePath + relPath
}

func resolveBaseURLForInit(urlVal, serverVal string) (baseURL string, serverName string, err error) {
	baseURL = strings.TrimSpace(urlVal)
	serverName = strings.TrimSpace(serverVal)

	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("AWEB_URL"))
	}
	if baseURL == "" && serverName != "" {
		baseURL, err = awconfig.DeriveBaseURLFromServerName(serverName)
		if err != nil {
			return "", "", err
		}
	}
	if baseURL == "" {
		baseURL = DefaultAwebURL
	}
	if serverName == "" {
		derived, derr := awconfig.DeriveServerNameFromURL(baseURL)
		if derr == nil {
			serverName = derived
		}
	}
	if err := awconfig.ValidateBaseURL(baseURL); err != nil {
		return "", "", err
	}
	baseURL, err = resolveWorkingBaseURL(baseURL)
	if err != nil {
		return "", "", err
	}
	return baseURL, serverName, nil
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func sanitizeSlug(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "demo"
	}
	return out
}

func bufferedPromptReader(in io.Reader) *bufio.Reader {
	if reader, ok := in.(*bufio.Reader); ok {
		return reader
	}
	return bufio.NewReader(in)
}

func promptStringWithIO(label, defaultValue string, in io.Reader, out io.Writer) (string, error) {
	reader := bufferedPromptReader(in)
	fmt.Fprintf(out, "%s [%s]: ", label, defaultValue)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue, nil
	}
	return line, nil
}

func promptString(label, defaultValue string) (string, error) {
	return promptStringWithIO(label, defaultValue, os.Stdin, os.Stderr)
}

func promptRequiredStringWithIO(label, suggestedValue string, in io.Reader, out io.Writer) (string, error) {
	reader := bufferedPromptReader(in)
	for {
		if strings.TrimSpace(suggestedValue) != "" {
			fmt.Fprintf(out, "%s [%s]: ", label, suggestedValue)
		} else {
			fmt.Fprintf(out, "%s: ", label)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
		if strings.TrimSpace(suggestedValue) != "" {
			return strings.TrimSpace(suggestedValue), nil
		}
		fmt.Fprintf(out, "%s is required.\n", label)
	}
}

func promptRequiredString(label, suggestedValue string) (string, error) {
	return promptRequiredStringWithIO(label, suggestedValue, os.Stdin, os.Stderr)
}

func promptIndexedChoice(label string, options []string, defaultIndex int, in io.Reader, out io.Writer) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("no options available")
	}
	hasDefault := defaultIndex >= 0 && defaultIndex < len(options)
	if !hasDefault {
		defaultIndex = -1
	}

	for i, option := range options {
		fmt.Fprintf(out, "  %d. %s\n", i+1, option)
	}

	reader := bufferedPromptReader(in)
	for {
		if hasDefault {
			fmt.Fprintf(out, "%s number [%d]: ", label, defaultIndex+1)
		} else {
			fmt.Fprintf(out, "%s number: ", label)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			if hasDefault {
				return options[defaultIndex], nil
			}
			fmt.Fprintf(out, "Enter a number between 1 and %d.\n", len(options))
			continue
		}
		index, err := strconv.Atoi(line)
		if err == nil && index >= 1 && index <= len(options) {
			return options[index-1], nil
		}
		fmt.Fprintf(out, "Enter a number between 1 and %d.\n", len(options))
	}
}

func sanitizeKeyComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "x"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "x"
	}
	return out
}

// deriveIdentityAddress builds the canonical external identity address from
// the identity domain plus the local routing handle or persistent name.
func deriveIdentityAddress(domain, handle string) string {
	if domain != "" {
		return domain + "/" + handle
	}
	return handle
}

func selectionAddress(sel *awconfig.Selection) string {
	if sel == nil {
		return ""
	}
	if address := strings.TrimSpace(sel.Address); address != "" {
		return address
	}
	return deriveIdentityAddress(strings.TrimSpace(sel.Domain), strings.TrimSpace(sel.Alias))
}

func handleFromAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	if idx := strings.LastIndexByte(address, '/'); idx >= 0 && idx+1 < len(address) {
		return strings.TrimSpace(address[idx+1:])
	}
	if idx := strings.LastIndexByte(address, '~'); idx >= 0 && idx+1 < len(address) {
		return strings.TrimSpace(address[idx+1:])
	}
	return address
}

func ensureWorktreeContextAt(workingDir string) error {
	ctxPath := filepath.Join(workingDir, awconfig.DefaultWorktreeContextRelativePath())
	if _, err := os.Stat(ctxPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return awconfig.SaveWorktreeContextTo(ctxPath, &awconfig.WorktreeContext{})
}

func printJSON(v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

func printOutput(v any, formatter func(v any) string) {
	if jsonFlag {
		printJSON(v)
		return
	}
	fmt.Print(formatter(v))
}

func parseTimeBestEffort(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return ts, true
	}
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts, true
	}
	return time.Time{}, false
}

func formatTimeAgo(timestamp string) string {
	ts, ok := parseTimeBestEffort(timestamp)
	if !ok {
		return timestamp
	}
	d := time.Since(ts)
	if d < 0 {
		d = 0
	}
	secs := int(d.Seconds())
	if secs < 60 {
		return fmt.Sprintf("%ds ago", secs)
	}
	mins := secs / 60
	if mins < 60 {
		return fmt.Sprintf("%dm ago", mins)
	}
	hours := mins / 60
	if hours < 48 {
		return fmt.Sprintf("%dh ago", hours)
	}
	days := hours / 24
	return fmt.Sprintf("%dd ago", days)
}

func formatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		mins := seconds / 60
		secs := seconds % 60
		if secs == 0 {
			return fmt.Sprintf("%dm", mins)
		}
		return fmt.Sprintf("%dm%ds", mins, secs)
	}
	hours := seconds / 3600
	mins := (seconds % 3600) / 60
	if mins == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh%dm", hours, mins)
}

func ttlRemainingSeconds(expiresAt string, now time.Time) int {
	if expiresAt == "" {
		return 0
	}
	ts, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return 0
		}
	}
	secs := int(math.Ceil(ts.Sub(now).Seconds()))
	if secs < 0 {
		return 0
	}
	return secs
}

// checkVerificationRequired detects EMAIL_VERIFICATION_REQUIRED 403 errors
// and returns a user-friendly message. Returns "" for non-matching errors.
func checkVerificationRequired(err error) string {
	statusCode, ok := awid.HTTPStatusCode(err)
	if !ok || statusCode != 403 {
		return ""
	}
	body, ok := awid.HTTPErrorBody(err)
	if !ok {
		return ""
	}
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Details struct {
				MaskedEmail string `json:"masked_email"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil || envelope.Error.Code != "EMAIL_VERIFICATION_REQUIRED" {
		return ""
	}
	hint := "email verification required"
	if envelope.Error.Details.MaskedEmail != "" {
		hint += " (" + envelope.Error.Details.MaskedEmail + ")"
	}
	hint += ". Verify this account in the dashboard, then re-run `aw init`."
	return hint
}

// networkError wraps an error with a user-friendly message for network 404 errors.
// When a network send fails because the target agent doesn't exist, the raw error
// is "aweb: http 404: ..." which looks like a broken endpoint. This rewrites it
// to mention the target address.
func networkError(err error, target string) error {
	code, ok := awid.HTTPStatusCode(err)
	if ok && code == 404 {
		return fmt.Errorf("agent not found: %s", target)
	}
	return err
}

// checkIdentityMismatch verifies that the resolved account matches
// the local workspace identity. Prevents silently running as the
// wrong agent when .aw/context resolves to a different account than
// .aw/workspace.yaml expects.
func checkIdentityMismatch(workingDir string, sel *awconfig.Selection) error {
	if sel == nil || strings.TrimSpace(sel.Alias) == "" {
		return nil
	}
	ws, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir)
	if err != nil || ws == nil {
		return nil
	}
	selectedMembership, err := workspaceMembershipForSelection(ws, sel)
	if err != nil || selectedMembership == nil {
		if err != nil {
			return err
		}
		return nil
	}
	wsAlias := strings.TrimSpace(selectedMembership.Alias)
	selAlias := strings.TrimSpace(sel.Alias)
	if wsAlias == "" || selAlias == "" {
		return nil
	}
	if wsAlias != selAlias {
		ctxPath := "(resolved from config)"
		if p, err := awconfig.FindWorktreeContextPath(workingDir); err == nil {
			ctxPath = p
		}
		wsPath := "(unknown)"
		if p, err := awconfig.FindWorktreeWorkspacePath(workingDir); err == nil {
			wsPath = p
		}
		return &identityMismatchError{
			ContextPath:    ctxPath,
			WorkspacePath:  wsPath,
			ResolvedAlias:  selAlias,
			WorkspaceAlias: wsAlias,
		}
	}
	return nil
}

func debugLog(format string, args ...any) {
	if debugFlag {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}

func workspaceMembershipForSelection(ws *awconfig.WorktreeWorkspace, sel *awconfig.Selection) (*awconfig.WorktreeMembership, error) {
	if ws == nil {
		return nil, nil
	}
	teamID := ""
	if sel != nil {
		teamID = strings.TrimSpace(sel.TeamID)
	}
	if teamID == "" {
		teamID = strings.TrimSpace(teamFlag)
	}
	if teamID != "" {
		if membership := ws.Membership(teamID); membership != nil {
			return membership, nil
		}
		return nil, fmt.Errorf("team %q is not present in workspace memberships; available: %s", teamID, strings.Join(ws.AvailableTeamIDs(), ", "))
	}
	return ws.ActiveMembership(), nil
}
