package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const agentStatusTestSeedEnv = "AW_AGENT_STATUS_TEST_SEED_HEX"

var statusHostCmd = &cobra.Command{Use: "status-host", Short: "Designate the current agent's status publisher", GroupID: groupCoordination}
var statusCmd = &cobra.Command{Use: "status", Short: "Publish signed agent health", GroupID: groupCoordination}

func init() {
	set := &cobra.Command{Use: "set", Short: "Designate a certified team member as your status host", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		host, _ := cmd.Flags().GetString("host-did")
		if strings.TrimSpace(host) == "" {
			return fmt.Errorf("--host-did is required")
		}
		return runStatusRequest(cmd, http.MethodPut, "/v1/agents/me/status-host", map[string]string{"host_did": host})
	}}
	set.Flags().String("host-did", "", "Status host's did:key")
	clear := &cobra.Command{Use: "clear", Short: "Clear your status host designation", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return runStatusRequest(cmd, http.MethodDelete, "/v1/agents/me/status-host", nil)
	}}
	show := &cobra.Command{Use: "show", Short: "Show your status host designation", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return runStatusRequest(cmd, http.MethodGet, "/v1/agents/me/status-host", nil)
	}}
	publish := &cobra.Command{Use: "publish", Short: "Sign and publish an agent-status-v1 JSON document", Args: cobra.NoArgs, RunE: runStatusPublish}
	publish.Flags().String("alias", "", "Subject agent's team alias")
	publish.Flags().String("document", "", "Read JSON from this file, or - for stdin")
	publish.Flags().Bool("print-signed", false, "Print only signed_payload and signature without network access")
	statusHostCmd.AddCommand(set, clear, show)
	statusCmd.AddCommand(publish)
	rootCmd.AddCommand(statusHostCmd, statusCmd)
}

func isAgentStatusCommand(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current == statusCmd || current == statusHostCmd {
			return true
		}
	}
	return false
}

// Execute also calls this for pre-run/flag/identity-selection errors, so --json
// always produces one object even when the command's RunE was never reached.
func statusInvocation(args []string) (bool, bool) {
	found, statusJSON := false, false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		switch arg {
		case "--identity-home", "--server-name", "--team":
			i++
			continue
		case "--json":
			statusJSON = true
			continue
		case "--json=true":
			statusJSON = true
			continue
		case "--json=false":
			statusJSON = false
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if !found {
			if arg != "status" && arg != "status-host" {
				return false, false
			}
			found = true
		}
	}
	return found, statusJSON
}

func normalizeStatusCommandError(args []string, err error) error {
	matched, outputJSON := statusInvocation(args)
	if !matched {
		return err
	}
	var statusError *statusCommandError
	if !errors.As(err, &statusError) {
		statusError = statusLocalError("local", err)
	}
	if outputJSON {
		printStatusCommandError(statusError)
	}
	return statusError
}

type statusCommandError struct {
	result map[string]any
	exit   int
}

func (e *statusCommandError) Error() string { return fmt.Sprint(e.result["message"]) }
func (e *statusCommandError) ExitCode() int { return e.exit }
func statusLocalError(code string, err error) *statusCommandError {
	return &statusCommandError{map[string]any{"ok": false, "status": nil, "code": code, "message": err.Error(), "retry_after": nil}, 1}
}
func printStatusCommandError(err error) {
	var refusal *statusCommandError
	if !errors.As(err, &refusal) {
		refusal = statusLocalError("local", err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(refusal.result)
}

func statusSigningIdentity() (*localSigningIdentity, string, error) {
	sel, err := resolveSelectionForDir("")
	if err != nil {
		return nil, "", err
	}
	home, err := identityHomeForDir(sel.WorkingDir)
	if err != nil {
		return nil, "", err
	}
	keyPath, err := awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return nil, "", err
	}
	key, err := awid.LoadSigningKey(keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load status signing key: %w", err)
	}
	identity := &localSigningIdentity{SigningKey: key, SigningKeyPath: keyPath,
		WorkingDir: sel.WorkingDir, IdentityHome: home.Root, TeamID: sel.TeamID,
		StableID: sel.StableID, Custody: sel.Custody}
	// Bind publisher_did to the loaded key, not an unchecked identity label.
	identity.DIDKey = awid.ComputeDIDKey(identity.SigningKey.Public().(ed25519.PublicKey))
	return identity, sel.BaseURL, nil
}

func runStatusPublish(cmd *cobra.Command, _ []string) error {
	offline, _ := cmd.Flags().GetBool("print-signed")
	seedHex, seedSet := os.LookupEnv(agentStatusTestSeedEnv)
	// An accidentally inherited fixture key must never sign an online request.
	if seedSet && seedHex != "" && !offline {
		return fmt.Errorf("%s is allowed only with --print-signed", agentStatusTestSeedEnv)
	}
	alias, _ := cmd.Flags().GetString("alias")
	if strings.TrimSpace(alias) == "" {
		return fmt.Errorf("--alias is required")
	}
	path, _ := cmd.Flags().GetString("document")
	if path == "" {
		return fmt.Errorf("--document is required (use - for stdin)")
	}
	var reader io.Reader = cmd.InOrStdin()
	var file *os.File
	if path != "-" {
		var err error
		file, err = os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		reader = file
	}
	raw, err := io.ReadAll(io.LimitReader(reader, 64*1024+1))
	if err != nil {
		return err
	}
	if len(raw) > 64*1024 {
		return fmt.Errorf("status input exceeds 65536 bytes")
	}
	var identity *localSigningIdentity
	var baseURL string
	if offline && seedHex != "" {
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("%s must contain exactly 32 bytes in hex", agentStatusTestSeedEnv)
		}
		key := ed25519.NewKeyFromSeed(seed)
		identity = &localSigningIdentity{SigningKey: key, DIDKey: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))}
	} else {
		identity, baseURL, err = statusSigningIdentity()
		if err != nil {
			return err
		}
	}
	signed, err := signAgentStatus(raw, identity)
	if err != nil {
		return err
	}
	if offline {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(signed)
	}
	return sendStatusRequest(cmd, identity, baseURL, http.MethodPut, "/v1/agents/"+url.PathEscape(alias)+"/status", signed)
}

func signAgentStatus(raw []byte, identity *localSigningIdentity) (map[string]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("invalid status JSON: %w", err)
	}
	if document == nil {
		return nil, fmt.Errorf("status document must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("status input must contain exactly one JSON object")
	}
	if document["publisher_did"] != identity.DIDKey {
		return nil, fmt.Errorf("publisher_did must equal the signing identity's did:key %s", identity.DIDKey)
	}
	payload, err := canonicalUTF8JSON(document)
	if err != nil {
		return nil, err
	}
	if len(payload) > 2048 {
		return nil, fmt.Errorf("canonical status document exceeds 2048 bytes")
	}
	return map[string]string{"signed_payload": base64.RawURLEncoding.EncodeToString(payload), "signature": base64.RawStdEncoding.EncodeToString(ed25519.Sign(identity.SigningKey, payload))}, nil
}

// canonicalUTF8JSON is the canonical encoding of signed status and activity
// documents: keys sorted by code point, no insignificant whitespace, raw UTF-8.
func canonicalUTF8JSON(document any) ([]byte, error) {
	canonical, err := awid.CanonicalJSONValue(document)
	if err != nil {
		return nil, err
	}
	// encoding/json always escapes U+2028/U+2029. Signed documents require
	// raw UTF-8; walk escape tokens so literal backslash-u text stays untouched.
	payload := []byte(canonical)
	var utf8 bytes.Buffer
	for i := 0; i < len(payload); {
		if payload[i] == '\\' && i+1 < len(payload) {
			if i+6 <= len(payload) && (string(payload[i:i+6]) == `\u2028` || string(payload[i:i+6]) == `\u2029`) {
				if payload[i+5] == '8' {
					utf8.WriteRune('\u2028')
				} else {
					utf8.WriteRune('\u2029')
				}
				i += 6
				continue
			}
			utf8.Write(payload[i : i+2])
			i += 2
			continue
		}
		utf8.WriteByte(payload[i])
		i++
	}
	return utf8.Bytes(), nil
}

func runStatusRequest(cmd *cobra.Command, method, path string, body any) error {
	identity, base, err := statusSigningIdentity()
	if err != nil {
		return err
	}
	return sendStatusRequest(cmd, identity, base, method, path, body)
}

var statusErrorCode = regexp.MustCompile(`^[a-z_]+$`)

func sendStatusRequest(cmd *cobra.Command, identity *localSigningIdentity, baseURL, method, path string, body any) error {
	base, err := cleanBaseURL(baseURL)
	if err != nil {
		return err
	}
	target, err := url.Parse(strings.TrimRight(base, "/") + path)
	if err != nil {
		return err
	}
	var raw []byte
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	// Reuse aw id request's team-auth v2 envelope (aud/method/path/body hash),
	// redirect refusal and response bounds. No message timestamps are injected
	// into the independently signed status document.
	if _, err := teamRequestCertificate(identity); err != nil {
		return err
	}
	response, err := executeSignedIDRequest(method, target, identity, raw, http.Header{}, nil, true)
	if err != nil {
		return statusLocalError("transport", err)
	}
	if response.Status < 200 || response.Status >= 300 {
		var message any = string(response.Body)
		var parsed struct {
			Detail json.RawMessage `json:"detail"`
		}
		if json.Unmarshal(response.Body, &parsed) == nil && len(parsed.Detail) > 0 {
			if json.Unmarshal(parsed.Detail, &message) != nil {
				message = string(parsed.Detail)
			}
		}
		code := "http"
		switch response.Status {
		case 401, 403:
			code = "auth"
		case 422:
			code = "request_shape"
		}
		if text, isString := message.(string); isString {
			if prefix, remainder, ok := strings.Cut(text, ": "); ok && statusErrorCode.MatchString(prefix) {
				code = prefix
				message = remainder
			}
		}
		var retry any
		if seconds, e := strconv.Atoi(response.Header.Get("Retry-After")); e == nil && seconds >= 0 {
			retry = seconds
		}
		return &statusCommandError{map[string]any{"ok": false, "status": response.Status, "code": code, "message": message, "retry_after": retry}, 3}
	}
	result := map[string]any{}
	if len(response.Body) > 0 {
		if err := json.Unmarshal(response.Body, &result); err != nil || result == nil {
			return fmt.Errorf("status server returned an invalid success object")
		}
	}
	result["ok"] = true
	result["status"] = response.Status
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}
	pretty, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(pretty))
	return err
}
