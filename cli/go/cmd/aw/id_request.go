package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type idSignOutput struct {
	DIDKey    string `json:"did_key"`
	Signature string `json:"signature"`
	Timestamp string `json:"timestamp"`
}

type idRequestOutput struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    any               `json:"body,omitempty"`
}

type localSigningIdentity struct {
	DIDKey         string
	StableID       string
	SigningKey     ed25519.PrivateKey
	SigningKeyPath string
	WorkingDir     string
	IdentityHome   string
	TeamID         string
	Custody        string
}

var (
	idSignPayload     string
	idSignPayloadFile string

	idRequestSign     string
	idRequestSignFile string
	idRequestBody     string
	idRequestBodyFile string
	idRequestHeaders  []string
	idRequestRaw      bool
	idRequestTeamAuth bool
)

var idSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign user data with a domain-separated local identity signature",
	RunE:  runIDSign,
}

var idRequestCmd = &cobra.Command{
	Use:   "request <method> <url>",
	Short: "Make a DIDKey-signed HTTP request with the local identity key",
	Args:  cobra.ExactArgs(2),
	RunE:  runIDRequest,
}

func init() {
	idSignCmd.Flags().StringVar(&idSignPayload, "payload", "", "JSON object to sign")
	idSignCmd.Flags().StringVar(&idSignPayloadFile, "payload-file", "", "Read the JSON payload to sign from a file")
	identityCmd.AddCommand(idSignCmd)

	idRequestCmd.Flags().StringVar(&idRequestSign, "sign", "", "Additional signed fields (requires --team-auth)")
	idRequestCmd.Flags().StringVar(&idRequestSignFile, "sign-file", "", "Read additional signed fields from a file (requires --team-auth)")
	idRequestCmd.Flags().StringVar(&idRequestBody, "body", "", shellExpandedInlineHelp("Request body to send", "--body-file"))
	idRequestCmd.Flags().StringVar(&idRequestBodyFile, "body-file", "", safeFileInputHelp("request body"))
	idRequestCmd.Flags().StringArrayVar(&idRequestHeaders, "header", nil, "Additional header in 'Name: Value' form")
	idRequestCmd.Flags().BoolVar(&idRequestTeamAuth, "team-auth", false, "Attach the active team certificate and sign a team-bound request payload")
	idRequestCmd.Flags().BoolVar(&idRequestRaw, "raw", false, "Print only the upstream response body")
	identityCmd.AddCommand(idRequestCmd)
}

func runIDSign(cmd *cobra.Command, args []string) error {
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	payload, err := loadJSONObjectInput(idSignPayload, idSignPayloadFile, "payload")
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	didKey, signature, _, err := awid.SignArbitraryPayload(identity.SigningKey, payload, timestamp)
	if err != nil {
		return err
	}
	printOutput(idSignOutput{
		DIDKey:    didKey,
		Signature: signature,
		Timestamp: timestamp,
	}, formatIDSign)
	return nil
}

func runIDRequest(cmd *cobra.Command, args []string) error {
	method := strings.ToUpper(strings.TrimSpace(args[0]))
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return usageError("unsupported method %q (use GET, POST, PUT, PATCH, or DELETE)", args[0])
	}

	targetURL := strings.TrimSpace(args[1])
	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return usageError("invalid url %q", targetURL)
	}

	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	bodyBytes, err := loadOptionalRequestBody(idRequestBody, idRequestBodyFile)
	if err != nil {
		return err
	}
	headers, err := parseRequestHeaderFlags(idRequestHeaders)
	if err != nil {
		return err
	}
	signPayload, err := loadIDRequestSignPayload(idRequestSign, idRequestSignFile)
	if err != nil {
		return err
	}

	result, err := executeSignedIDRequest(method, parsedURL, identity, bodyBytes, headers, signPayload, idRequestTeamAuth)
	if err != nil {
		return err
	}
	return printIDRequestExecutionResult(result, idRequestRaw)
}

type idRequestExecutionResult struct {
	Status int
	Header http.Header
	Body   []byte
}

func executeSignedIDRequest(method string, parsedURL *url.URL, identity *localSigningIdentity, bodyBytes []byte, headers http.Header, signPayload map[string]any, teamAuth bool) (*idRequestExecutionResult, error) {
	if err := signIDRequestHeaders(headers, method, parsedURL, identity, bodyBytes, signPayload, teamAuth, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}

	ctx, cancel := commandAPIContext(nil)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header = headers.Clone()
	awid.TraceHTTPRequest(req, bodyBytes)

	client := &http.Client{
		Timeout:   awid.APITimeout(),
		Transport: awid.NewAPITransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := awid.TraceHTTPResponse(resp); err != nil {
		return nil, err
	}

	responseBody, err := readAllBounded(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return &idRequestExecutionResult{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: responseBody}, nil
}

func signIDRequestHeaders(headers http.Header, method string, parsedURL *url.URL, identity *localSigningIdentity, bodyBytes []byte, signPayload map[string]any, teamAuth bool, timestamp string) error {
	if headers == nil {
		return fmt.Errorf("headers are required")
	}
	if identity == nil || len(identity.SigningKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("local signing identity is required")
	}
	claim, value := "did_aw", strings.TrimSpace(identity.StableID)
	if teamAuth {
		cert, err := teamRequestCertificate(identity)
		if err != nil {
			return err
		}
		certHeader, err := awid.EncodeTeamCertificateHeader(cert)
		if err != nil {
			return fmt.Errorf("encode team certificate header: %w", err)
		}
		headers.Set("X-AWID-Team-Certificate", certHeader)
		claim, value = "team_id", strings.TrimSpace(identity.TeamID)
	} else {
		if len(signPayload) != 0 {
			return usageError("--sign fields require --team-auth")
		}
		headers.Del("X-AWID-Team-Certificate")
	}
	didKey, signature, canonical, err := awid.SignRequestCredential(identity.SigningKey, method, parsedURL, claim, value, timestamp, bodyBytes, signPayload)
	if err != nil {
		return err
	}
	headers.Set("Authorization", fmt.Sprintf("DIDKey %s %s", didKey, signature))
	headers.Set("X-AWEB-Timestamp", timestamp)
	headers.Set("X-AWEB-Signed-Payload", base64.RawURLEncoding.EncodeToString([]byte(canonical)))
	headers.Set("X-AWEB-DID-AW", strings.TrimSpace(identity.StableID))
	if len(bodyBytes) > 0 && strings.TrimSpace(headers.Get("Content-Type")) == "" {
		headers.Set("Content-Type", "application/json")
	}
	return nil
}

func printIDRequestExecutionResult(result *idRequestExecutionResult, raw bool) error {
	if result == nil {
		return fmt.Errorf("missing response")
	}
	if raw {
		if _, err := commandStdout.Write(result.Body); err != nil {
			return err
		}
		if len(result.Body) > 0 && result.Body[len(result.Body)-1] != '\n' {
			fmt.Fprintln(commandStdout)
		}
		fmt.Fprintf(os.Stderr, "HTTP %d\n", result.Status)
	} else {
		printOutput(idRequestOutput{
			Status:  result.Status,
			Headers: flattenResponseHeaders(result.Header),
			Body:    decodeResponseBody(result.Body),
		}, formatIDRequest)
	}
	if result.Status >= 400 {
		return fmt.Errorf("request failed with status %d", result.Status)
	}
	return nil
}

func resolveLocalSigningIdentity() (*localSigningIdentity, error) {
	sel, err := resolveSelectionForDir("")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(sel.Custody) != "" && strings.TrimSpace(sel.Custody) != awid.CustodySelf {
		return nil, usageError("current identity has no local signing key")
	}
	signingKeyPath := strings.TrimSpace(sel.SigningKey)
	if signingKeyPath == "" && strings.TrimSpace(sel.WorkingDir) != "" {
		candidate := filepath.Join(sel.IdentityHome, "signing.key")
		if strings.TrimSpace(sel.IdentityHome) == "" {
			candidate = awconfig.WorktreeSigningKeyPath(strings.TrimSpace(sel.WorkingDir))
		}
		if _, err := os.Stat(candidate); err == nil {
			signingKeyPath = candidate
		}
	}
	if signingKeyPath == "" {
		return nil, usageError("current identity has no local signing key")
	}
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	didKey := strings.TrimSpace(sel.DID)
	if didKey == "" {
		didKey = awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	}
	return &localSigningIdentity{
		DIDKey:         didKey,
		StableID:       strings.TrimSpace(sel.StableID),
		SigningKey:     signingKey,
		SigningKeyPath: signingKeyPath,
		WorkingDir:     strings.TrimSpace(sel.WorkingDir),
		IdentityHome:   strings.TrimSpace(sel.IdentityHome),
		TeamID:         strings.TrimSpace(sel.TeamID),
		Custody:        strings.TrimSpace(sel.Custody),
	}, nil
}

func loadIDRequestSignPayload(inline, filePath string) (map[string]any, error) {
	if strings.TrimSpace(inline) == "" && strings.TrimSpace(filePath) == "" {
		return map[string]any{}, nil
	}
	return loadJSONObjectInput(inline, filePath, "sign")
}

func teamRequestCertificate(identity *localSigningIdentity) (*awid.TeamCertificate, error) {
	if identity == nil {
		return nil, fmt.Errorf("local signing identity is required")
	}
	if strings.TrimSpace(identity.WorkingDir) == "" || strings.TrimSpace(identity.TeamID) == "" {
		return nil, usageError("--team-auth requires an aw workspace with an active team")
	}
	var cert *awid.TeamCertificate
	var err error
	if strings.TrimSpace(identity.IdentityHome) != "" {
		certPath, pathErr := awconfig.IdentityHomeStoredPath(awconfig.IdentityHome{Root: identity.IdentityHome}, awconfig.TeamCertificateRelativePath(identity.TeamID))
		if pathErr != nil {
			return nil, pathErr
		}
		cert, err = awid.LoadTeamCertificate(certPath)
	} else {
		cert, err = awconfig.LoadTeamCertificateForTeam(identity.WorkingDir, identity.TeamID)
	}
	if err != nil {
		return nil, fmt.Errorf("load active team certificate: %w", err)
	}
	if strings.TrimSpace(cert.Team) != strings.TrimSpace(identity.TeamID) {
		return nil, fmt.Errorf("active team certificate team_id %q does not match selected team %q", cert.Team, identity.TeamID)
	}
	if strings.TrimSpace(cert.MemberDIDKey) != strings.TrimSpace(identity.DIDKey) {
		return nil, fmt.Errorf("active team certificate member_did_key %q does not match local signing key %q", cert.MemberDIDKey, identity.DIDKey)
	}

	return cert, nil
}

func loadJSONObjectInput(inline, filePath, flagName string) (map[string]any, error) {
	raw, err := loadExclusiveStringInput(inline, filePath, flagName)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var payload any
	if err := decoder.Decode(&payload); err != nil {
		return nil, usageError("invalid %s JSON: %v", flagName, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, usageError("invalid %s JSON: %v", flagName, err)
	}
	object, ok := payload.(map[string]any)
	if !ok {
		return nil, usageError("%s must be a JSON object", flagName)
	}
	return object, nil
}

func loadExclusiveStringInput(inline, filePath, flagName string) (string, error) {
	inline = strings.TrimSpace(inline)
	filePath = strings.TrimSpace(filePath)
	if inline != "" && filePath != "" {
		return "", usageError("use only one of --%s or --%s-file", flagName, flagName)
	}
	switch {
	case filePath != "":
		data, err := readFileBounded(filePath, maxBodyFileBytes)
		if err != nil {
			return "", err
		}
		return string(data), nil
	case inline != "":
		return inline, nil
	default:
		return "", usageError("missing required flag: --%s or --%s-file", flagName, flagName)
	}
}

func loadOptionalRequestBody(inline, filePath string) ([]byte, error) {
	inline = strings.TrimSpace(inline)
	filePath = strings.TrimSpace(filePath)
	if inline != "" && filePath != "" {
		return nil, usageError("use only one of --body or --body-file")
	}
	switch {
	case filePath != "":
		return readFileBounded(filePath, maxBodyFileBytes)
	case inline != "":
		return []byte(inline), nil
	default:
		return nil, nil
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("unexpected trailing data")
}

func parseRequestHeaderFlags(values []string) (http.Header, error) {
	headers := make(http.Header)
	for _, value := range values {
		name, rawValue, ok := strings.Cut(value, ":")
		if !ok {
			return nil, usageError("invalid --header %q (expected 'Name: Value')", value)
		}
		name = strings.TrimSpace(name)
		rawValue = strings.TrimSpace(rawValue)
		if name == "" {
			return nil, usageError("invalid --header %q (missing header name)", value)
		}
		headers.Add(name, rawValue)
	}
	return headers, nil
}

func flattenResponseHeaders(headers http.Header) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, strings.ToLower(strings.TrimSpace(key)))
	}
	slices.Sort(keys)

	flat := make(map[string]string, len(keys))
	for _, key := range keys {
		values := headers.Values(key)
		if len(values) == 0 {
			continue
		}
		flat[key] = strings.Join(values, ", ")
	}
	return flat
}

func decodeResponseBody(data []byte) any {
	if len(data) == 0 {
		return ""
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err == nil {
		if ensureJSONEOF(decoder) == nil {
			return value
		}
	}
	return string(data)
}
