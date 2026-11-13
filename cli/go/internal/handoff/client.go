package handoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

const maxReplyBytes = 1 << 20

// Scope names a holding: the installation, the role and the principal.
type Scope struct {
	InstallationID string `json:"installation_id"`
	Role           string `json:"role"`
	Principal      string `json:"principal"`
}

// Origins are the installation's two pinned origins: the app origin, where
// team-auth is admitted, and the human origin, which refuses it.
type Origins struct {
	App   string
	Human string
}

// Signer sends a request to the app origin signed with team-auth v2 as the
// holder, following no redirect.
type Signer func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error)

// Options configure one handoff.
type Options struct {
	Origins Origins
	Scope   Scope
	Sign    Signer
	// Open opens a URL in the local browser. Its failure is reported, not
	// fatal: the URL is always printed too.
	Open func(url string) error
	// Notify receives the URL and what the human is to do.
	Notify io.Writer
	// HTTP sends the requests to the human origin.
	HTTP *http.Client
}

// Session is a console session bound to the handoff's ephemeral key.
type Session struct {
	ID        string
	CSRF      string
	ExpiresAt time.Time
	Scope     Scope

	key    ed25519.PrivateKey
	origin string
	http   *http.Client
}

// Credential is the public credential a credential handoff registered.
type Credential struct {
	CredentialID string `json:"credential_id"`
	PublicKey    string `json:"public_key"`
	RPID         string `json:"rp_id"`
}

// Response is an answer from the human origin.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// OpenSession runs a session handoff and returns the console session.
func OpenSession(ctx context.Context, opts Options) (*Session, error) {
	key, reply, err := run(ctx, opts, "session")
	if err != nil {
		return nil, err
	}
	var result struct {
		Purpose   string `json:"purpose"`
		SessionID string `json:"session_id"`
		CSRFToken string `json:"csrf_token"`
		ExpiresAt string `json:"expires_at"`
		Scope     Scope  `json:"scope"`
	}
	if err := json.Unmarshal(reply, &result); err != nil {
		return nil, invalidResult(err)
	}
	expires, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil || result.Purpose != "session" || result.SessionID == "" || result.CSRFToken == "" || result.Scope != opts.Scope {
		return nil, invalidResult(errors.New("the result is not a session for the requested scope"))
	}
	return &Session{
		ID: result.SessionID, CSRF: result.CSRFToken, ExpiresAt: expires, Scope: result.Scope,
		key: key, origin: opts.Origins.Human, http: noRedirects(opts.HTTP),
	}, nil
}

// RegisterCredential runs a credential handoff and returns the public
// credential the browser registered at the human origin.
func RegisterCredential(ctx context.Context, opts Options) (*Credential, error) {
	_, reply, err := run(ctx, opts, "credential")
	if err != nil {
		return nil, err
	}
	var result struct {
		Purpose    string     `json:"purpose"`
		Credential Credential `json:"credential"`
	}
	if err := json.Unmarshal(reply, &result); err != nil {
		return nil, invalidResult(err)
	}
	human, err := url.Parse(opts.Origins.Human)
	if err != nil {
		return nil, err
	}
	c := result.Credential
	if result.Purpose != "credential" || c.CredentialID == "" || c.PublicKey == "" || c.RPID != human.Hostname() {
		return nil, invalidResult(errors.New("the result is not a credential at the human origin"))
	}
	return &c, nil
}

// Do sends a request in the session to the human origin. path is the raw
// request target relative to that origin. A state-changing request carries
// the CSRF token. Every answer is returned as given, refusals included.
func (s *Session) Do(ctx context.Context, method, path string, body []byte) (*Response, error) {
	req, err := s.request(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	return receive(s.http, req)
}

// DoTo is Do for a response too large to hold: a 2xx body is copied to w
// uncapped and Response.Body is empty. Any other answer writes nothing to w
// and returns its body, capped, in Response.Body. A failed copy is an error.
func (s *Session) DoTo(ctx context.Context, method, path string, body []byte, w io.Writer) (*Response, error) {
	req, err := s.request(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		reply, err := readReply(resp)
		if err != nil {
			return nil, err
		}
		return &Response{Status: resp.StatusCode, Header: resp.Header, Body: reply}, nil
	}
	defer resp.Body.Close()
	if _, err := io.Copy(w, resp.Body); err != nil {
		return nil, fmt.Errorf("copy the response: %w", err)
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header}, nil
}

func (s *Session) request(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	target, err := url.Parse(s.origin + path)
	if err != nil {
		return nil, err
	}
	headers, err := consoleHeaders(s.key, consoleRequest{
		Auth: "handoff-session", Audience: s.origin, Method: method, Path: target.RequestURI(),
		SubjectField: "session_id", Subject: s.ID, Body: body, Timestamp: time.Now(), Nonce: newNonce(),
	})
	if err != nil {
		return nil, err
	}
	if method != http.MethodGet {
		headers.Set("X-CSRF-Token", s.CSRF)
	}
	return newRequest(ctx, method, target, headers, body)
}

func run(ctx context.Context, opts Options, purpose string) (ed25519.PrivateKey, []byte, error) {
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	verifier := randomToken()
	loopback, err := ListenLoopback()
	if err != nil {
		return nil, nil, err
	}
	defer loopback.Close()
	handoffID, expires, err := start(ctx, opts, purpose, key, verifier, loopback.RedirectURI())
	if err != nil {
		return nil, nil, err
	}
	loopback.Expect(handoffID)
	page := opts.Origins.Human + "/handoff/" + url.PathEscape(handoffID)
	fmt.Fprintf(opts.Notify, "Open this page to continue: %s\n", page)
	if opts.Open != nil {
		if err := opts.Open(page); err != nil {
			fmt.Fprintf(opts.Notify, "Could not open a browser (%v); open the page above yourself.\n", err)
		}
	}
	code, err := loopback.Wait(ctx, expires)
	if err != nil {
		return nil, nil, err
	}
	reply, err := collect(ctx, opts, key, handoffID, code, verifier)
	return key, reply, err
}

func start(ctx context.Context, opts Options, purpose string, key ed25519.PrivateKey, verifier, redirectURI string) (string, time.Time, error) {
	digest := sha256.Sum256([]byte(verifier))
	body, err := json.Marshal(map[string]any{
		"v": 1, "purpose": purpose, "client_key": awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)),
		"return": "loopback", "redirect_uri": redirectURI, "verifier_sha256": hex.EncodeToString(digest[:]),
		"scope": opts.Scope,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	target, err := url.Parse(opts.Origins.App + "/handoffs")
	if err != nil {
		return "", time.Time{}, err
	}
	resp, err := opts.Sign(ctx, http.MethodPost, target, body)
	if err != nil {
		return "", time.Time{}, err
	}
	reply, err := readReply(resp)
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, refusal(resp.StatusCode, reply)
	}
	var started struct {
		HandoffID string `json:"handoff_id"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(reply, &started); err != nil || started.HandoffID == "" {
		return "", time.Time{}, invalidResult(errors.New("the start answered no handoff id"))
	}
	expires, err := time.Parse(time.RFC3339, started.ExpiresAt)
	if err != nil {
		return "", time.Time{}, invalidResult(err)
	}
	return started.HandoffID, expires, nil
}

func collect(ctx context.Context, opts Options, key ed25519.PrivateKey, handoffID, code, verifier string) ([]byte, error) {
	target, err := url.Parse(opts.Origins.Human + "/handoffs/" + url.PathEscape(handoffID) + "/result")
	if err != nil {
		return nil, err
	}
	body, err := awid.CanonicalJSONValue(map[string]any{"v": 1, "code": code, "verifier": verifier})
	if err != nil {
		return nil, err
	}
	headers, err := consoleHeaders(key, consoleRequest{
		Auth: "handoff-result", Audience: opts.Origins.Human, Method: http.MethodPost, Path: target.RequestURI(),
		SubjectField: "handoff_id", Subject: handoffID, Body: []byte(body), Timestamp: time.Now(), Nonce: newNonce(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := send(ctx, noRedirects(opts.HTTP), http.MethodPost, target, headers, []byte(body))
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, refusal(resp.Status, resp.Body)
	}
	return resp.Body, nil
}

func send(ctx context.Context, client *http.Client, method string, target *url.URL, headers http.Header, body []byte) (*Response, error) {
	req, err := newRequest(ctx, method, target, headers, body)
	if err != nil {
		return nil, err
	}
	return receive(client, req)
}

func newRequest(ctx context.Context, method string, target *url.URL, headers http.Header, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = headers
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func receive(client *http.Client, req *http.Request) (*Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	reply, err := readReply(resp)
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: reply}, nil
}

func readReply(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(reply) > maxReplyBytes {
		return nil, coded("handoff_reply_too_large", errors.New("the app's answer exceeds 1 MiB"))
	}
	return reply, nil
}

// noRedirects is client, or the default client, with redirects returned
// rather than followed.
func noRedirects(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	copied := *client
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copied
}

// refusal is the app's coded answer, under its own code when it names one.
func refusal(status int, body []byte) error {
	code := RefusalCode(body)
	if code == "" {
		code = "handoff_http_" + fmt.Sprint(status)
	}
	return told(code, fmt.Errorf("the app answered %d", status), Facts{})
}

// RefusalCode is the `detail` code of an app's refusal body, or "".
func RefusalCode(body []byte) string {
	var reply struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(body, &reply) != nil {
		return ""
	}
	code, _ := reply.Detail.(string)
	if strings.ContainsAny(code, " \n") || len(code) > 64 {
		return ""
	}
	return code
}

func invalidResult(err error) error { return coded("handoff_result_invalid", err) }

// randomToken is 32 random bytes in unpadded base64url.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
