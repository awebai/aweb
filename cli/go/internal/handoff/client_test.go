package handoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// appStub answers the handoff routes with fixed replies. It stands in for
// the app only to observe what aw sends and how aw treats each answer; the
// real app's verifier is exercised by the real-path test.
type appStub struct {
	t           *testing.T
	server      *httptest.Server
	mu          sync.Mutex
	start       map[string]any
	result      *http.Request
	resultBody  []byte
	startStatus int
	startReply  map[string]any
	resultReply map[string]any
	session     []*http.Request
}

func newAppStub(t *testing.T) *appStub {
	s := &appStub{t: t, startStatus: http.StatusCreated}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

func (s *appStub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/app/handoffs":
		_ = json.Unmarshal(body, &s.start)
		w.WriteHeader(s.startStatus)
		reply := s.startReply
		if reply == nil {
			reply = map[string]any{"handoff_id": "h1", "expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
		}
		_ = json.NewEncoder(w).Encode(reply)
		if s.startStatus == http.StatusCreated {
			go s.browserReturns(s.start["redirect_uri"].(string))
		}
	case r.Method == http.MethodPost && r.URL.Path == "/human/handoffs/h1/result":
		s.result, s.resultBody = r, body
		_ = json.NewEncoder(w).Encode(s.resultReply)
	case strings.HasPrefix(r.URL.Path, "/human/redirect"):
		http.Redirect(w, r, "/human/elsewhere", http.StatusFound)
	default:
		s.session = append(s.session, r)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
}

// browserReturns plays the browser following the app's redirect to aw.
func (s *appStub) browserReturns(redirectURI string) {
	for i := 0; i < 50; i++ {
		resp, err := http.Get(redirectURI + "?handoff_id=h1&code=" + testCode)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *appStub) options(t *testing.T) (Options, *string) {
	scope := Scope{InstallationID: "00000000-0000-4000-8000-000000000001", Role: "secrets.owner", Principal: "did:aw:holder"}
	opened := ""
	return Options{
		Origins: Origins{App: s.server.URL + "/app", Human: s.server.URL + "/human"},
		Scope:   scope,
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			return http.DefaultClient.Do(req)
		},
		Open:   func(u string) error { opened = u; return nil },
		Notify: io.Discard,
		HTTP:   http.DefaultClient,
	}, &opened
}

func sessionReply(scope Scope) map[string]any {
	return map[string]any{
		"purpose": "session", "session_id": "s1", "csrf_token": "c1",
		"expires_at": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
		"scope":      map[string]any{"installation_id": scope.InstallationID, "role": scope.Role, "principal": scope.Principal},
	}
}

func TestASessionHandoffStartsOnTheAppOriginAndCollectsOnTheHumanOrigin(t *testing.T) {
	app := newAppStub(t)
	opts, opened := app.options(t)
	app.resultReply = sessionReply(opts.Scope)
	session, err := OpenSession(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if session.ID != "s1" || session.CSRF != "c1" {
		t.Fatalf("session %+v", session)
	}
	if *opened != opts.Origins.Human+"/handoff/h1" {
		t.Fatalf("opened %q", *opened)
	}
	start := app.start
	if start["purpose"] != "session" || start["return"] != "loopback" || start["v"] != float64(1) {
		t.Fatalf("start %v", start)
	}
	if _, ok := start["client_hostname"]; ok {
		t.Fatalf("a loopback start sends no hostname: %v", start)
	}
	var result map[string]any
	if err := json.Unmarshal(app.resultBody, &result); err != nil {
		t.Fatal(err)
	}
	if result["code"] != testCode || result["v"] != float64(1) || len(result) != 3 {
		t.Fatalf("result body %v", result)
	}
	verifierDigest := sha256.Sum256([]byte(result["verifier"].(string)))
	if start["verifier_sha256"] != hex.EncodeToString(verifierDigest[:]) {
		t.Fatal("the verifier does not match its registered digest")
	}
	// The result is signed by the key the start registered, for the human origin.
	headers := app.result.Header
	if headers.Get("X-Console-Key") != start["client_key"] {
		t.Fatalf("key %q, start registered %q", headers.Get("X-Console-Key"), start["client_key"])
	}
	payload, _ := base64.RawURLEncoding.DecodeString(headers.Get("X-Console-Signed-Payload"))
	var signed map[string]any
	_ = json.Unmarshal(payload, &signed)
	if signed["aud"] != opts.Origins.Human || signed["auth"] != "handoff-result" || signed["handoff_id"] != "h1" || signed["path"] != "/human/handoffs/h1/result" {
		t.Fatalf("signed %v", signed)
	}
	pub, err := awid.ExtractPublicKey(start["client_key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.RawStdEncoding.DecodeString(headers.Get("X-Console-Signature"))
	if !ed25519.Verify(pub, payload, sig) {
		t.Fatal("result signature does not verify under the registered key")
	}
	for _, name := range []string{"Authorization", "X-Awid-Team-Certificate", "X-Aweb-Signature"} {
		if headers.Get(name) != "" {
			t.Fatalf("team-auth header %s sent to the human origin", name)
		}
	}
}

func TestAStartRefusalEndsTheHandoffWithItsCode(t *testing.T) {
	for status, code := range map[int]string{
		http.StatusForbidden:    "role_not_held",
		http.StatusUnauthorized: "console_session_required",
		http.StatusConflict:     "fallback_unavailable",
	} {
		app := newAppStub(t)
		app.startStatus = status
		app.startReply = map[string]any{"detail": code}
		opts, _ := app.options(t)
		_, err := OpenSession(context.Background(), opts)
		if ErrorCode(err) != code {
			t.Fatalf("%d: err %v", status, err)
		}
		if app.result != nil {
			t.Fatalf("%d: collected a result after a refused start", status)
		}
	}
}

func TestASessionForAnotherScopeIsRefused(t *testing.T) {
	app := newAppStub(t)
	opts, _ := app.options(t)
	other := opts.Scope
	other.Principal = "did:aw:someone-else"
	app.resultReply = sessionReply(other)
	if _, err := OpenSession(context.Background(), opts); ErrorCode(err) != "handoff_result_invalid" {
		t.Fatalf("err %v", err)
	}
}

func TestSessionRequestsAreSignedAndCarryCSRFOnlyWhenTheyChangeState(t *testing.T) {
	app := newAppStub(t)
	opts, _ := app.options(t)
	app.resultReply = sessionReply(opts.Scope)
	session, err := OpenSession(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Do(context.Background(), http.MethodGet, "/installations/i/change-sets/c?x=1", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Do(context.Background(), http.MethodPost, "/installations/i/change-sets", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	get, post := app.session[0], app.session[1]
	if get.Header.Get("X-CSRF-Token") != "" || post.Header.Get("X-CSRF-Token") != "c1" {
		t.Fatalf("csrf get %q post %q", get.Header.Get("X-CSRF-Token"), post.Header.Get("X-CSRF-Token"))
	}
	payload, _ := base64.RawURLEncoding.DecodeString(get.Header.Get("X-Console-Signed-Payload"))
	var signed map[string]any
	_ = json.Unmarshal(payload, &signed)
	if signed["auth"] != "handoff-session" || signed["session_id"] != "s1" || signed["path"] != "/human/installations/i/change-sets/c?x=1" {
		t.Fatalf("signed %v", signed)
	}
	if get.Header.Get("X-Console-Signed-Payload") == post.Header.Get("X-Console-Signed-Payload") {
		t.Fatal("two requests share a payload")
	}
}

func TestSessionRequestsFollowNoRedirect(t *testing.T) {
	app := newAppStub(t)
	opts, _ := app.options(t)
	app.resultReply = sessionReply(opts.Scope)
	session, err := OpenSession(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := session.Do(context.Background(), http.MethodGet, "/redirect", nil)
	if err == nil && resp.Status == http.StatusFound {
		return
	}
	t.Fatalf("resp %+v err %v", resp, err)
}

// errWriter fails every write.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func openedSession(t *testing.T, serve http.HandlerFunc) *Session {
	t.Helper()
	server := httptest.NewServer(serve)
	t.Cleanup(server.Close)
	_, key, _ := ed25519.GenerateKey(nil)
	return &Session{ID: "s1", CSRF: "c1", key: key, origin: server.URL, http: noRedirects(http.DefaultClient)}
}

func TestDoToStreamsASuccessfulBodyUncapped(t *testing.T) {
	large := bytes.Repeat([]byte("x"), maxReplyBytes+10)
	session := openedSession(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Console-Signed-Payload") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=logs-t.jsonl")
		_, _ = w.Write(large)
	})
	var out bytes.Buffer
	resp, err := session.DoTo(context.Background(), http.MethodGet, "/v1/export", nil, &out)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusOK || len(resp.Body) != 0 || !bytes.Equal(out.Bytes(), large) || resp.Header.Get("Content-Disposition") == "" {
		t.Fatalf("status %d body %d out %d", resp.Status, len(resp.Body), out.Len())
	}
}

func TestDoToWritesNothingForARefusal(t *testing.T) {
	session := openedSession(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"console_session_required"}`))
	})
	var out bytes.Buffer
	resp, err := session.DoTo(context.Background(), http.MethodGet, "/v1/export", nil, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || RefusalCode(resp.Body) != "console_session_required" {
		t.Fatalf("out %q body %s", out.String(), resp.Body)
	}
}

func TestDoToReturnsACopyFailureAsAnError(t *testing.T) {
	session := openedSession(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("data")) })
	if _, err := session.DoTo(context.Background(), http.MethodGet, "/v1/export", nil, errWriter{}); err == nil {
		t.Fatal("a failed copy reported success")
	}
}

func TestDoToFollowsNoRedirect(t *testing.T) {
	session := openedSession(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			_, _ = w.Write([]byte("followed"))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	var out bytes.Buffer
	resp, err := session.DoTo(context.Background(), http.MethodGet, "/v1/export", nil, &out)
	if err != nil || resp.Status != http.StatusFound || out.Len() != 0 {
		t.Fatalf("resp %+v out %q err %v", resp, out.String(), err)
	}
}
