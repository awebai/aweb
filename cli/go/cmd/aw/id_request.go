package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

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
	SigningKey     ed25519.PrivateKey
	SigningKeyPath string
	Custody        string
	Lifetime       string
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
)

var idSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a canonical JSON payload with the local identity key",
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

	idRequestCmd.Flags().StringVar(&idRequestSign, "sign", "", "JSON object describing the signed payload fields")
	idRequestCmd.Flags().StringVar(&idRequestSignFile, "sign-file", "", "Read the JSON sign payload from a file")
	idRequestCmd.Flags().StringVar(&idRequestBody, "body", "", "Request body to send")
	idRequestCmd.Flags().StringVar(&idRequestBodyFile, "body-file", "", "Read the request body from a file")
	idRequestCmd.Flags().StringArrayVar(&idRequestHeaders, "header", nil, "Additional header in 'Name: Value' form")
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
	signPayload, err := loadJSONObjectInput(idRequestSign, idRequestSignFile, "sign")
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

	timestamp := time.Now().UTC().Format(time.RFC3339)
	didKey, signature, _, err := awid.SignArbitraryPayload(identity.SigningKey, signPayload, timestamp)
	if err != nil {
		return err
	}
	headers.Set("Authorization", fmt.Sprintf("DIDKey %s %s", didKey, signature))
	headers.Set("X-AWEB-Timestamp", timestamp)
	if len(bodyBytes) > 0 && strings.TrimSpace(headers.Get("Content-Type")) == "" {
		headers.Set("Content-Type", "application/json")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header = headers.Clone()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if idRequestRaw {
		if _, err := os.Stdout.Write(responseBody); err != nil {
			return err
		}
		if len(responseBody) > 0 && responseBody[len(responseBody)-1] != '\n' {
			fmt.Fprintln(os.Stdout)
		}
		fmt.Fprintf(os.Stderr, "HTTP %d\n", resp.StatusCode)
	} else {
		printOutput(idRequestOutput{
			Status:  resp.StatusCode,
			Headers: flattenResponseHeaders(resp.Header),
			Body:    decodeResponseBody(responseBody),
		}, formatIDRequest)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
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
	if strings.TrimSpace(sel.SigningKey) == "" {
		return nil, usageError("current identity has no local signing key")
	}
	signingKey, err := awid.LoadSigningKey(strings.TrimSpace(sel.SigningKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}
	didKey := strings.TrimSpace(sel.DID)
	if didKey == "" {
		didKey = awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	}
	return &localSigningIdentity{
		DIDKey:         didKey,
		SigningKey:     signingKey,
		SigningKeyPath: strings.TrimSpace(sel.SigningKey),
		Custody:        strings.TrimSpace(sel.Custody),
		Lifetime:       strings.TrimSpace(sel.Lifetime),
	}, nil
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
		data, err := os.ReadFile(filePath)
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
		return os.ReadFile(filePath)
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
