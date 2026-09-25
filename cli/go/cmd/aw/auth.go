package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const (
	cliAuthClientID           = "aweb-cli"
	cliAuthScope              = "cli.personal_workspace"
	cliAuthScopeTeamAdmission = "cli.team_admission"
	cliAuthDeviceGrant        = "urn:ietf:params:oauth:grant-type:device_code"
	cliAuthTokenType          = "bearer"
	cliAuthDefaultTimeout     = 10 * time.Minute
)

var (
	cliAuthLoginTimeout time.Duration
	cliAuthScopeFlag    string
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate this host aw CLI to a human aweb account",
	Long: "Authenticate this host aw CLI to a human aweb account.\n\n" +
		"Credentials are stored only in the host aw config directory, not in workspace or identity homes.",
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Start browser-based device login for this host aw CLI",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), cliAuthLoginTimeout)
		defer cancel()
		return runAuthLogin(ctx, cmd)
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show host CLI human-auth status without printing tokens",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuthStatus(cmd.Context(), cmd)
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke host CLI human-auth tokens and remove local credentials",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuthLogout(cmd.Context(), cmd)
	},
}

func init() {
	authLoginCmd.Flags().DurationVar(&cliAuthLoginTimeout, "timeout", cliAuthDefaultTimeout, "Maximum time to wait for browser approval")
	authLoginCmd.Flags().StringVar(&cliAuthScopeFlag, "scope", cliAuthScope, "CLI authorization scope (cli.personal_workspace|cli.team_admission)")
	authStatusCmd.Flags().StringVar(&cliAuthScopeFlag, "scope", cliAuthScope, "CLI authorization scope to inspect")
	authLogoutCmd.Flags().StringVar(&cliAuthScopeFlag, "scope", cliAuthScope, "CLI authorization scope to revoke")
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authLogoutCmd)
	authCmd.GroupID = groupIdentity
	rootCmd.AddCommand(authCmd)
	identityHomeNeutralCommandExemptions[authLoginCmd] = struct{}{}
	identityHomeNeutralCommandExemptions[authStatusCmd] = struct{}{}
	identityHomeNeutralCommandExemptions[authLogoutCmd] = struct{}{}
}

type cliAuthConfig struct {
	Issuer       string    `json:"issuer"`
	Resource     string    `json:"resource"`
	Scope        string    `json:"scope"`
	ClientID     string    `json:"client_id"`
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type cliDeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Resource                string `json:"resource"`
	Scope                   string `json:"scope"`
}

type cliTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Resource     string `json:"resource"`
}

type cliOAuthError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type cliAuthAudienceError struct {
	Message string
}

func (e *cliAuthAudienceError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *cliOAuthError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.ErrorDescription) != "" {
		return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
	}
	return e.ErrorCode
}

type cliAuthStatusOutput struct {
	Status    string `json:"status"`
	Issuer    string `json:"issuer,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func runAuthLogin(ctx context.Context, cmd *cobra.Command) error {
	loadDotenvBestEffort()
	scope, err := selectedCLIAuthScope()
	if err != nil {
		return err
	}
	issuer, err := resolveCLIAuthIssuer("")
	if err != nil {
		return err
	}
	resource := cliAuthResource(issuer)
	device, err := requestCLIAuthDeviceCode(ctx, issuer, resource, scope)
	if err != nil {
		return err
	}
	if strings.TrimSpace(device.DeviceCode) == "" {
		return errors.New("auth login: server response missing device_code")
	}
	if strings.TrimSpace(device.UserCode) == "" {
		return errors.New("auth login: server response missing user_code")
	}
	if strings.TrimSpace(device.VerificationURIComplete) == "" && strings.TrimSpace(device.VerificationURI) == "" {
		return errors.New("auth login: server response missing verification URI")
	}

	if jsonFlag {
		out := map[string]any{
			"status":                    "pending",
			"client_id":                 cliAuthClientID,
			"resource":                  firstNonEmptyString(device.Resource, resource),
			"scope":                     firstNonEmptyString(device.Scope, scope),
			"user_code":                 device.UserCode,
			"verification_uri":          device.VerificationURI,
			"verification_uri_complete": device.VerificationURIComplete,
			"expires_in":                device.ExpiresIn,
			"interval":                  device.Interval,
		}
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(out); err != nil {
			return err
		}
	} else {
		approval := firstNonEmptyString(device.VerificationURIComplete, device.VerificationURI)
		fmt.Fprintf(cmd.OutOrStdout(), "Open this URL to approve aw CLI login:\n%s\n\nUser code: %s\n", approval, device.UserCode)
	}

	token, err := pollCLIAuthDeviceToken(ctx, issuer, resource, device)
	if err != nil {
		return err
	}
	if err := validateCLIAuthTokenResponse(token, resource, scope); err != nil {
		return err
	}
	cfg := cliAuthConfigFromToken(issuer, resource, scope, token, time.Now().UTC())
	if err := saveCLIAuthConfigForScope(scope, cfg); err != nil {
		return err
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(cliAuthStatusOutput{Status: "authorized", Issuer: issuer, Resource: resource, Scope: scope, ExpiresAt: cfg.ExpiresAt.Format(time.RFC3339)})
	}
	fmt.Fprintln(cmd.OutOrStdout(), "aw CLI login authorized")
	return nil
}

func runAuthStatus(ctx context.Context, cmd *cobra.Command) error {
	loadDotenvBestEffort()
	scope, err := selectedCLIAuthScope()
	if err != nil {
		return err
	}
	cfg, ok, err := loadCLIAuthConfigForScope(scope)
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(cfg.AccessToken) == "" {
		return printCLIAuthStatus(cmd, cliAuthStatusOutput{Status: "missing"})
	}
	if cfg.ClientID != cliAuthClientID || strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Resource) == "" {
		return printCLIAuthStatus(cmd, cliAuthStatusOutput{Status: "missing"})
	}
	if err := validateStoredCLIAuthAudience(cfg, scope); err != nil {
		return err
	}
	if time.Now().UTC().After(cfg.ExpiresAt) {
		refreshed, refreshErr := refreshCLIAuthToken(ctx, cfg)
		if refreshErr != nil {
			var audienceErr *cliAuthAudienceError
			if errors.As(refreshErr, &audienceErr) {
				return refreshErr
			}
			return printCLIAuthStatus(cmd, cliAuthStatusOutput{Status: "expired", Issuer: cfg.Issuer, Resource: cfg.Resource, Scope: cfg.Scope, ExpiresAt: cfg.ExpiresAt.Format(time.RFC3339)})
		}
		cfg = refreshed
		if err := saveCLIAuthConfigForScope(scope, cfg); err != nil {
			return err
		}
	}
	status, err := requestCLIAuthServerStatus(ctx, cfg)
	if err != nil {
		var oauthErr *cliOAuthError
		if errors.As(err, &oauthErr) && oauthErr.ErrorCode == "expired" {
			return printCLIAuthStatus(cmd, cliAuthStatusOutput{Status: "expired", Issuer: cfg.Issuer, Resource: cfg.Resource, Scope: cfg.Scope, ExpiresAt: cfg.ExpiresAt.Format(time.RFC3339)})
		}
		return err
	}
	if strings.TrimSpace(status.Status) == "" {
		status.Status = "authorized"
	}
	status.Issuer = cfg.Issuer
	status.Resource = cfg.Resource
	status.Scope = cfg.Scope
	status.ExpiresAt = cfg.ExpiresAt.Format(time.RFC3339)
	return printCLIAuthStatus(cmd, status)
}

func runAuthLogout(ctx context.Context, cmd *cobra.Command) error {
	loadDotenvBestEffort()
	scope, err := selectedCLIAuthScope()
	if err != nil {
		return err
	}
	cfg, ok, err := loadCLIAuthConfigForScope(scope)
	if err != nil {
		return err
	}
	if !ok || (strings.TrimSpace(cfg.AccessToken) == "" && strings.TrimSpace(cfg.RefreshToken) == "") {
		return printCLIAuthStatus(cmd, cliAuthStatusOutput{Status: "missing"})
	}
	var failures []string
	if strings.TrimSpace(cfg.AccessToken) != "" {
		if err := revokeCLIAuthToken(ctx, cfg.Issuer, cfg.AccessToken, "access_token"); err != nil {
			failures = append(failures, "access_token")
		}
	}
	if strings.TrimSpace(cfg.RefreshToken) != "" {
		if err := revokeCLIAuthToken(ctx, cfg.Issuer, cfg.RefreshToken, "refresh_token"); err != nil {
			failures = append(failures, "refresh_token")
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("auth logout: server revocation failed for %s; local credentials were retained", strings.Join(failures, ", "))
	}
	if err := removeCLIAuthConfigForScope(scope); err != nil {
		return err
	}
	return printCLIAuthStatus(cmd, cliAuthStatusOutput{Status: "missing"})
}

func printCLIAuthStatus(cmd *cobra.Command, out cliAuthStatusOutput) error {
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "status: %s\n", out.Status)
	if out.Issuer != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "issuer: %s\n", out.Issuer)
	}
	if out.Resource != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "resource: %s\n", out.Resource)
	}
	if out.Scope != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "scope: %s\n", out.Scope)
	}
	if out.ExpiresAt != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "expires_at: %s\n", out.ExpiresAt)
	}
	return nil
}

func requestCLIAuthDeviceCode(ctx context.Context, issuer, resource, scope string) (*cliDeviceAuthorizationResponse, error) {
	values := url.Values{}
	values.Set("client_id", cliAuthClientID)
	values.Set("scope", scope)
	values.Set("resource", resource)
	var out cliDeviceAuthorizationResponse
	if err := postCLIAuthForm(ctx, issuer, "/oauth/device_authorization", values, "", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func pollCLIAuthDeviceToken(ctx context.Context, issuer, resource string, device *cliDeviceAuthorizationResponse) (*cliTokenResponse, error) {
	interval := device.Interval
	if interval <= 0 {
		interval = 1
	}
	for {
		values := url.Values{}
		values.Set("grant_type", cliAuthDeviceGrant)
		values.Set("client_id", cliAuthClientID)
		values.Set("device_code", device.DeviceCode)
		values.Set("resource", resource)
		var token cliTokenResponse
		err := postCLIAuthForm(ctx, issuer, "/oauth/token", values, "", &token)
		if err == nil {
			return &token, nil
		}
		var oauthErr *cliOAuthError
		if !errors.As(err, &oauthErr) {
			return nil, err
		}
		switch oauthErr.ErrorCode {
		case "authorization_pending":
			// wait below
		case "slow_down":
			interval += 5
		case "access_denied":
			return nil, errors.New("auth login denied by browser approval")
		case "expired_token":
			return nil, errors.New("auth login device code expired")
		case "invalid_grant", "invalid_client", "invalid_target", "invalid_scope":
			return nil, fmt.Errorf("auth login failed: %s", oauthErr.ErrorCode)
		default:
			return nil, fmt.Errorf("auth login failed: %s", oauthErr.ErrorCode)
		}
		timer := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, errors.New("auth login timed out waiting for browser approval")
		case <-timer.C:
		}
	}
}

func refreshCLIAuthToken(ctx context.Context, cfg cliAuthConfig) (cliAuthConfig, error) {
	if strings.TrimSpace(cfg.RefreshToken) == "" {
		return cfg, errors.New("missing refresh token")
	}
	values := url.Values{}
	values.Set("grant_type", "refresh_token")
	values.Set("client_id", cliAuthClientID)
	values.Set("refresh_token", cfg.RefreshToken)
	values.Set("resource", cfg.Resource)
	var token cliTokenResponse
	if err := postCLIAuthForm(ctx, cfg.Issuer, "/oauth/token", values, "", &token); err != nil {
		return cfg, err
	}
	if err := validateCLIAuthTokenResponse(&token, cfg.Resource, cfg.Scope); err != nil {
		return cfg, err
	}
	return cliAuthConfigFromToken(cfg.Issuer, cfg.Resource, cfg.Scope, &token, time.Now().UTC()), nil
}

func revokeCLIAuthToken(ctx context.Context, issuer, token, hint string) error {
	values := url.Values{}
	values.Set("client_id", cliAuthClientID)
	values.Set("token", token)
	if strings.TrimSpace(hint) != "" {
		values.Set("token_type_hint", hint)
	}
	return postCLIAuthForm(ctx, issuer, "/oauth/revoke", values, "", nil)
}

func requestCLIAuthServerStatus(ctx context.Context, cfg cliAuthConfig) (cliAuthStatusOutput, error) {
	var out cliAuthStatusOutput
	if err := getCLIAuthJSON(ctx, cfg.Issuer, "/api/v1/cli-auth/status", cfg.AccessToken, &out); err != nil {
		return cliAuthStatusOutput{}, err
	}
	return out, nil
}

func postCLIAuthForm(ctx context.Context, issuer, path string, values url.Values, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(issuer, "/")+path, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(bearer) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearer))
	}
	return doCLIAuthJSON(req, out)
}

func getCLIAuthJSON(ctx context.Context, issuer, path, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(bearer) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearer))
	}
	return doCLIAuthJSON(req, out)
}

func doCLIAuthJSON(req *http.Request, out any) error {
	client := &http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}
	resp, err := awid.DoNoRedirectWithTimeout(client, req, awid.APITimeout())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, awid.MaxResponseSize))
		var oauthErr cliOAuthError
		if json.Unmarshal(data, &oauthErr) == nil && strings.TrimSpace(oauthErr.ErrorCode) != "" {
			if resp.StatusCode == http.StatusUnauthorized && oauthErr.ErrorCode == "" {
				oauthErr.ErrorCode = "expired"
			}
			return &oauthErr
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return &cliOAuthError{ErrorCode: "expired", ErrorDescription: "stored CLI access token is not authorized"}
		}
		return fmt.Errorf("auth request failed: http %d", resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, awid.MaxResponseSize))
		return nil
	}
	data, err := awid.ReadAllBounded(resp.Body, awid.MaxResponseSize)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func validateCLIAuthTokenResponse(token *cliTokenResponse, expectedResource, expectedScope string) error {
	if token == nil {
		return errors.New("auth token response missing")
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return errors.New("auth token response missing access_token")
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		return errors.New("auth token response missing refresh_token")
	}
	if tokenType := strings.ToLower(strings.TrimSpace(token.TokenType)); tokenType != "" && tokenType != cliAuthTokenType {
		return fmt.Errorf("auth token response has unsupported token_type %q", token.TokenType)
	}
	if got := strings.TrimSpace(token.Resource); got != "" && got != expectedResource {
		return &cliAuthAudienceError{Message: fmt.Sprintf("auth token response resource %q does not match CLI resource %q", got, expectedResource)}
	}
	if got := strings.TrimSpace(token.Scope); got != "" && got != expectedScope {
		return &cliAuthAudienceError{Message: fmt.Sprintf("auth token response scope %q does not match CLI scope %q", got, expectedScope)}
	}
	return nil
}

func validateStoredCLIAuthAudience(cfg cliAuthConfig, expectedScope string) error {
	expectedResource := cliAuthResource(cfg.Issuer)
	if got := strings.TrimSpace(cfg.Resource); got != "" && got != expectedResource {
		return &cliAuthAudienceError{Message: fmt.Sprintf("stored CLI auth resource %q does not match expected CLI resource %q", got, expectedResource)}
	}
	if got := strings.TrimSpace(cfg.Scope); got != "" && got != expectedScope {
		return &cliAuthAudienceError{Message: fmt.Sprintf("stored CLI auth scope %q does not match expected CLI scope %q", got, expectedScope)}
	}
	return nil
}

func cliAuthConfigFromToken(issuer, resource, scope string, token *cliTokenResponse, now time.Time) cliAuthConfig {
	expiresIn := token.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	return cliAuthConfig{
		Issuer:       issuer,
		Resource:     firstNonEmptyString(token.Resource, resource),
		Scope:        firstNonEmptyString(token.Scope, scope),
		ClientID:     cliAuthClientID,
		AccessToken:  strings.TrimSpace(token.AccessToken),
		RefreshToken: strings.TrimSpace(token.RefreshToken),
		TokenType:    firstNonEmptyString(strings.ToLower(strings.TrimSpace(token.TokenType)), cliAuthTokenType),
		ExpiresAt:    now.Add(time.Duration(expiresIn) * time.Second),
		UpdatedAt:    now,
	}
}

func resolveCLIAuthIssuer(existing string) (string, error) {
	raw := strings.TrimSpace(serverFlag)
	if raw == "" {
		raw = strings.TrimSpace(existing)
	}
	if raw == "" {
		raw = DefaultAwebURL
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		derived, err := awconfig.DeriveBaseURLFromServerName(raw)
		if err != nil {
			return "", err
		}
		raw = derived
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid auth issuer URL %q", raw)
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path == "/api" {
		parsed.Path = ""
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func selectedCLIAuthScope() (string, error) {
	scope := strings.TrimSpace(cliAuthScopeFlag)
	if scope == "" {
		scope = cliAuthScope
	}
	switch scope {
	case cliAuthScope, cliAuthScopeTeamAdmission:
		return scope, nil
	default:
		return "", usageError("unsupported CLI auth scope %q", scope)
	}
}

func cliAuthResource(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/cli"
}

func cliAuthConfigPath() (string, error) {
	return cliAuthConfigPathForScope(cliAuthScope)
}

func cliAuthConfigPathForScope(scope string) (string, error) {
	scope = strings.TrimSpace(scope)
	if scope == "" || scope == cliAuthScope {
		return awconfig.PathInUserState("auth.json")
	}
	if scope == cliAuthScopeTeamAdmission {
		return awconfig.PathInUserState("auth.cli_team_admission.json")
	}
	return "", fmt.Errorf("unsupported CLI auth scope %q", scope)
}

func loadCLIAuthConfig() (cliAuthConfig, bool, error) {
	return loadCLIAuthConfigForScope(cliAuthScope)
}

func loadCLIAuthConfigForScope(scope string) (cliAuthConfig, bool, error) {
	path, err := cliAuthConfigPathForScope(scope)
	if err != nil {
		return cliAuthConfig{}, false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cliAuthConfig{}, false, nil
	}
	if err != nil {
		return cliAuthConfig{}, false, err
	}
	var cfg cliAuthConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cliAuthConfig{}, false, fmt.Errorf("read auth config: %w", err)
	}
	return cfg, true, nil
}

func saveCLIAuthConfig(cfg cliAuthConfig) error {
	return saveCLIAuthConfigForScope(cliAuthScope, cfg)
}

func saveCLIAuthConfigForScope(scope string, cfg cliAuthConfig) error {
	path, err := cliAuthConfigPathForScope(scope)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return awid.AtomicWriteFile(path, data)
}

func removeCLIAuthConfig() error {
	return removeCLIAuthConfigForScope(cliAuthScope)
}

func removeCLIAuthConfigForScope(scope string) error {
	path, err := cliAuthConfigPathForScope(scope)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		_ = os.Chmod(dir, 0o700)
	}
	return nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
