package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/manualclock"
	awrun "github.com/awebai/aw/run"
)

// A server whose API is mounted under /api while the workspace stores the
// server's origin as aweb_url. These tests sign with a real team certificate
// and the server checks, for every signed request, which path it was signed
// for.

const answeringMountHeaderForTest = "X-Aw-Client-Answering-Mount"

// signedRequestSeen is one signed request as the server received it: the path
// it arrived at, and whether its v2 envelope verifies for that path.
type signedRequestSeen struct {
	Path           string
	SignedForIt    bool
	SignedForWhich string
}

type movedMountServer struct {
	*httptest.Server
	mu       sync.Mutex
	signed   []signedRequestSeen
	unsigned []string
	// streamAnswer is what the stream under /api does with a request signed
	// for it: http.StatusOK serves it, any other status refuses with it, and
	// zero drops the connection without answering.
	streamAnswer int
	// noAPIMount makes /api answer 404 like every other path.
	noAPIMount bool
	// sentMountHeader, when set, is sent on every 404 under the name the
	// client keeps for the mount that answers.
	sentMountHeader string
}

// verifyV2SignedRequest checks the request's v2 envelope: the signature is the
// sender's over the signed payload, and the payload names this request's
// audience, method and path.
func verifyV2SignedRequest(r *http.Request) (signedPath string, ok bool) {
	auth := strings.Fields(r.Header.Get("Authorization"))
	if len(auth) != 3 || auth[0] != "DIDKey" {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if err != nil {
		return "", false
	}
	var fields struct {
		V      int    `json:"v"`
		Aud    string `json:"aud"`
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if json.Unmarshal(payload, &fields) != nil {
		return "", false
	}
	signature, err := base64.RawStdEncoding.DecodeString(auth[2])
	if err != nil {
		return fields.Path, false
	}
	pub, err := awid.ExtractPublicKey(auth[1])
	if err != nil || !ed25519.Verify(pub, payload, signature) {
		return fields.Path, false
	}
	return fields.Path, fields.V == 2 && fields.Aud == "http://"+r.Host && fields.Method == r.Method && fields.Path == r.URL.RequestURI()
}

func newMovedMountServer(t *testing.T) *movedMountServer {
	t.Helper()
	ms := &movedMountServer{streamAnswer: http.StatusOK}
	ms.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ms.mu.Lock()
		streamAnswer, noAPIMount, sentMountHeader := ms.streamAnswer, ms.noAPIMount, ms.sentMountHeader
		signedForIt := false
		if r.Header.Get("Authorization") != "" {
			signedPath, ok := verifyV2SignedRequest(r)
			signedForIt = ok
			ms.signed = append(ms.signed, signedRequestSeen{Path: r.URL.Path, SignedForIt: ok, SignedForWhich: signedPath})
		} else {
			ms.unsigned = append(ms.unsigned, r.Method+" "+r.URL.Path)
		}
		ms.mu.Unlock()

		notFound := func() {
			if sentMountHeader != "" {
				w.Header().Set(answeringMountHeaderForTest, sentMountHeader)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"Not Found"}`))
		}
		if noAPIMount || !strings.HasPrefix(r.URL.Path, "/api/") {
			notFound()
			return
		}
		switch strings.TrimPrefix(r.URL.Path, "/api") {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/agents/heartbeat":
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			notFound()
		case "/v1/events/stream":
			if !signedForIt {
				http.Error(w, `{"detail":"signature does not cover this request"}`, http.StatusUnauthorized)
				return
			}
			switch streamAnswer {
			case http.StatusOK:
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("event: connected\ndata: {\"agent_id\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"team_id\":\"backend:demo\"}\n\n"))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			case 0:
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
			default:
				http.Error(w, `{"detail":"refused"}`, streamAnswer)
			}
		default:
			notFound()
		}
	}))
	t.Cleanup(ms.Close)
	return ms
}

func (ms *movedMountServer) set(change func(*movedMountServer)) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	change(ms)
}

func (ms *movedMountServer) signedSeen() []signedRequestSeen {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return append([]signedRequestSeen(nil), ms.signed...)
}

func (ms *movedMountServer) unsignedCount(request string) int {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	count := 0
	for _, seen := range ms.unsigned {
		if seen == request {
			count++
		}
	}
	return count
}

// movedMountWorkspace writes a certificate workspace whose stored aweb_url is
// storedURL and returns the working directory and the workspace file.
func movedMountWorkspace(t *testing.T, storedURL string) (workingDir, workspacePath string) {
	t.Helper()
	root := resolvedTempDir(t)
	isolateIdentityResolution(t, root)
	workingDir = filepath.Join(root, "work")
	if err := os.MkdirAll(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return workingDir, writeNetworkWorkspace(t, workingDir, storedURL, "", "")
}

func storedAwebURL(t *testing.T, workspacePath string) string {
	t.Helper()
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	return workspace.AwebURL
}

func answeringMountHintForTest(mount string) string {
	return "The server answers at " + mount + ". The configured server URL should be that: set aweb_url in workspace.yaml to " + mount + "."
}

func requireNotFoundNamingMount(t *testing.T, err error, mount string) {
	t.Helper()
	if status, ok := awid.HTTPStatusCode(err); !ok || status != http.StatusNotFound {
		t.Fatalf("err=%v, want the server's 404", err)
	}
	if body, _ := awid.HTTPErrorBody(err); body != `{"detail":"Not Found"}` {
		t.Fatalf("404 body %q, want the server's body unchanged", body)
	}
	if want := answeringMountHintForTest(mount); !strings.Contains(err.Error(), want) {
		t.Fatalf("error does not name the mount that answers.\n got: %s\nwant it to contain: %s", err.Error(), want)
	}
}

func openStreamOnce(opener awrun.EventStreamOpener) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	source, err := opener(ctx, time.Now().Add(time.Minute))
	if err == nil {
		_ = source.Close()
	}
	return err
}

// A signed stream open that meets a 404 at the stored server URL is sent once,
// to the path it was signed for. The caller gets that 404 naming the mount
// that answers, and the stored server URL stays as it was.
func TestSignedStreamOpenAt404BaseIsSentOnceAndNamesTheAnsweringMount(t *testing.T) {
	server := newMovedMountServer(t)
	workingDir, workspacePath := movedMountWorkspace(t, server.URL)

	client, _, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.EventStream(ctx, time.Now().Add(time.Minute))
	if err == nil {
		_ = stream.Close()
		t.Fatal("the stream opened; the stored server URL answers 404")
	}
	requireNotFoundNamingMount(t, err, server.URL+"/api")

	want := []signedRequestSeen{{Path: "/v1/events/stream", SignedForIt: true}}
	got := server.signedSeen()
	for i := range got {
		got[i].SignedForWhich = ""
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("signed requests the server saw: %+v, want exactly %+v", got, want)
	}
	if stored := storedAwebURL(t, workspacePath); stored != server.URL {
		t.Fatalf("stored aweb_url=%q, want it unchanged at %q", stored, server.URL)
	}
}

// A signed command request at the 404 base gets the hint, is not sent anywhere
// else and stores nothing. The mount that answers is looked for once per
// client.
func TestSignedRequestAt404BaseGetsTheHintAndStoresNothing(t *testing.T) {
	server := newMovedMountServer(t)
	workingDir, workspacePath := movedMountWorkspace(t, server.URL)

	client, _, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, err = client.Heartbeat(context.Background())
		requireNotFoundNamingMount(t, err, server.URL+"/api")
	}

	for _, seen := range server.signedSeen() {
		if seen.Path != "/v1/agents/heartbeat" || !seen.SignedForIt {
			t.Fatalf("signed request %+v, want only requests at the path they were signed for under the stored server URL", seen)
		}
	}
	if count := len(server.signedSeen()); count != 2 {
		t.Fatalf("the server saw %d signed requests, want 2: one per call", count)
	}
	if probes := server.unsignedCount("GET /api/v1/agents/heartbeat"); probes != 1 {
		t.Fatalf("the mount under /api was probed %d times, want once for the client", probes)
	}
	if stored := storedAwebURL(t, workspacePath); stored != server.URL {
		t.Fatalf("stored aweb_url=%q, want it unchanged at %q", stored, server.URL)
	}
}

// A 404 from a server URL that answers as the API is the API's own answer:
// it carries no hint, and the server URL is probed once per client.
func TestNotFoundAtAnAnsweringServerURLCarriesNoHint(t *testing.T) {
	server := newMovedMountServer(t)
	workingDir, workspacePath := movedMountWorkspace(t, server.URL+"/api")

	client, _, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		err = client.Get(context.Background(), "/v1/tasks/missing", nil)
		if status, ok := awid.HTTPStatusCode(err); !ok || status != http.StatusNotFound {
			t.Fatalf("err=%v, want the server's 404", err)
		}
		if strings.Contains(err.Error(), "answers at") {
			t.Fatalf("a 404 from the API itself carries a hint: %s", err.Error())
		}
	}
	if probes := server.unsignedCount("GET /api/v1/agents/heartbeat"); probes != 1 {
		t.Fatalf("the stored server URL was probed %d times, want once for the client", probes)
	}
	if stored := storedAwebURL(t, workspacePath); stored != server.URL+"/api" {
		t.Fatalf("stored aweb_url=%q, want it unchanged", stored)
	}
}

// The header that carries the answering mount to the error display is the
// client's own. A value the server sends under that name is dropped: it is
// never shown, whether or not the client finds a mount itself.
func TestServerSentAnsweringMountHeaderIsNeverRendered(t *testing.T) {
	t.Run("no mount answers", func(t *testing.T) {
		server := newMovedMountServer(t)
		server.set(func(ms *movedMountServer) {
			ms.noAPIMount = true
			ms.sentMountHeader = ms.URL + "/api"
		})
		workingDir, _ := movedMountWorkspace(t, server.URL)
		client, _, err := resolveClientSelectionForDir(workingDir)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Heartbeat(context.Background())
		if status, ok := awid.HTTPStatusCode(err); !ok || status != http.StatusNotFound {
			t.Fatalf("err=%v, want the server's 404", err)
		}
		if strings.Contains(err.Error(), "answers at") || strings.Contains(err.Error(), "/api") {
			t.Fatalf("the server's own header value was rendered: %s", err.Error())
		}
	})
	t.Run("a mount answers", func(t *testing.T) {
		server := newMovedMountServer(t)
		server.set(func(ms *movedMountServer) { ms.sentMountHeader = ms.URL + "/elsewhere" })
		workingDir, _ := movedMountWorkspace(t, server.URL)
		client, _, err := resolveClientSelectionForDir(workingDir)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Heartbeat(context.Background())
		requireNotFoundNamingMount(t, err, server.URL+"/api")
		if strings.Contains(err.Error(), "/elsewhere") {
			t.Fatalf("the server's own header value was rendered: %s", err.Error())
		}
	})
	t.Run("another origin", func(t *testing.T) {
		// A client with no transport of its own to drop the header: the
		// display still refuses a mount that is not on the request's origin.
		server := newMovedMountServer(t)
		server.set(func(ms *movedMountServer) {
			ms.noAPIMount = true
			ms.sentMountHeader = "http://other.invalid/api"
		})
		client, err := awid.New(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		err = client.Get(context.Background(), "/v1/tasks/missing", nil)
		if status, ok := awid.HTTPStatusCode(err); !ok || status != http.StatusNotFound {
			t.Fatalf("err=%v, want the server's 404", err)
		}
		if strings.Contains(err.Error(), "answers at") || strings.Contains(err.Error(), "other.invalid") {
			t.Fatalf("a mount on another origin was rendered: %s", err.Error())
		}
	})
}

// `aw run`: the client built at start is signed for the stored server URL and
// is refused with 404. The retry goes through runEventStreamReload, which
// finds the mount that answers and builds a client that signs for it. The
// stored server URL changes once that stream has opened.
func TestRunEventStreamSignsForTheAnsweringMountAfterAReload(t *testing.T) {
	server := newMovedMountServer(t)
	workingDir, workspacePath := movedMountWorkspace(t, server.URL)

	client, _, err := runResolveClientForDir(workingDir)
	if err != nil {
		t.Fatal(err)
	}
	clock := manualclock.New(time.Now())
	bus := awrun.NewEventBus(awrun.EventBusConfig{
		Stream: awrun.NewEventStreamOpener(client.Client),
		Reload: runEventStreamReload(workingDir),
		Now:    clock.Now,
		Policy: awrun.StreamPolicyConfig{Timer: clock.Timer, Rand: clock.Random},
	})
	ctx, cancel := context.WithCancel(context.Background())
	bus.Start(ctx)
	defer func() {
		cancel()
		bus.Stop()
	}()

	// First attempt: planned-close timer, then the wait after the refusal.
	if !clock.AwaitStarted(2, 1) {
		t.Fatal("the bus is not waiting to retry after the first refusal")
	}
	if bus.State() != awrun.ConnRefused {
		t.Fatalf("state=%s after the stored server URL answered 404", bus.State())
	}
	if stored := storedAwebURL(t, workspacePath); stored != server.URL {
		t.Fatalf("stored aweb_url=%q after the refusal, want it unchanged at %q", stored, server.URL)
	}

	clock.Advance(time.Minute)
	waitForCondition(t, "the stream to be accepted at the mount that answers", func() bool { return bus.State() == awrun.ConnStreaming })

	want := []signedRequestSeen{
		{Path: "/v1/events/stream", SignedForIt: true},
		{Path: "/api/v1/events/stream", SignedForIt: true},
	}
	got := server.signedSeen()
	for i := range got {
		if !strings.HasPrefix(got[i].SignedForWhich, got[i].Path+"?deadline=") {
			t.Fatalf("request at %s carried a payload signed for %q", got[i].Path, got[i].SignedForWhich)
		}
		got[i].SignedForWhich = ""
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("signed requests the server saw: %+v, want exactly %+v", got, want)
	}
	waitForCondition(t, "the answering mount to be stored", func() bool { return storedAwebURL(t, workspacePath) == server.URL+"/api" })
}

// The two reloads that find the answering mount: `aw run`'s and the wake
// broker's opener, which the broker calls again before a refused retry.
func answeringMountReloads(workingDir string) map[string]awrun.StreamReload {
	return map[string]awrun.StreamReload{
		"aw run": runEventStreamReload(workingDir),
		"wake broker": func(ctx context.Context) (awrun.EventStreamOpener, error) {
			return wakeStreamOpener(ctx, awconfig.WorktreeIdentityHome(workingDir), "")
		},
	}
}

// The answering mount is stored only after a stream signed for it has opened
// there. A refused open and an open that fails store nothing.
func TestReloadStoresTheAnsweringMountOnlyAfterItsStreamOpens(t *testing.T) {
	for _, name := range []string{"aw run", "wake broker"} {
		for _, failing := range []struct {
			name   string
			answer int
		}{{"refused with 401", http.StatusUnauthorized}, {"refused with 403", http.StatusForbidden}, {"server error", http.StatusServiceUnavailable}, {"connection dropped", 0}} {
			t.Run(name+"/"+failing.name, func(t *testing.T) {
				server := newMovedMountServer(t)
				server.set(func(ms *movedMountServer) { ms.streamAnswer = failing.answer })
				workingDir, workspacePath := movedMountWorkspace(t, server.URL)

				opener, err := answeringMountReloads(workingDir)[name](context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := openStreamOnce(opener); err == nil {
					t.Fatal("the stream opened; the server does not serve it")
				}
				seen := server.signedSeen()
				if len(seen) != 1 || seen[0].Path != "/api/v1/events/stream" || !seen[0].SignedForIt {
					t.Fatalf("signed requests the server saw: %+v, want one, at the answering mount and signed for it", seen)
				}
				if stored := storedAwebURL(t, workspacePath); stored != server.URL {
					t.Fatalf("stored aweb_url=%q after a failed open, want it unchanged at %q", stored, server.URL)
				}

				server.set(func(ms *movedMountServer) { ms.streamAnswer = http.StatusOK })
				if err := openStreamOnce(opener); err != nil {
					t.Fatalf("open at the answering mount: %v", err)
				}
				if stored := storedAwebURL(t, workspacePath); stored != server.URL+"/api" {
					t.Fatalf("stored aweb_url=%q after the stream opened, want %q", stored, server.URL+"/api")
				}
				for _, seen := range server.signedSeen() {
					if seen.Path != "/api/v1/events/stream" || !seen.SignedForIt {
						t.Fatalf("signed request %+v, want only requests at the answering mount signed for it", seen)
					}
				}
			})
		}
	}
}

// A reload that finds no other mount builds for the stored server URL and
// stores nothing.
func TestReloadWithNoOtherMountBuildsForTheStoredServerURL(t *testing.T) {
	for _, name := range []string{"aw run", "wake broker"} {
		t.Run(name, func(t *testing.T) {
			server := newMovedMountServer(t)
			server.set(func(ms *movedMountServer) { ms.noAPIMount = true })
			workingDir, workspacePath := movedMountWorkspace(t, server.URL)

			opener, err := answeringMountReloads(workingDir)[name](context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := openStreamOnce(opener); err == nil {
				t.Fatal("the stream opened; the server serves none")
			}
			seen := server.signedSeen()
			if len(seen) != 1 || seen[0].Path != "/v1/events/stream" || !seen[0].SignedForIt {
				t.Fatalf("signed requests the server saw: %+v, want one, at the stored server URL and signed for it", seen)
			}
			if stored := storedAwebURL(t, workspacePath); stored != server.URL {
				t.Fatalf("stored aweb_url=%q, want it unchanged at %q", stored, server.URL)
			}
		})
	}
}

// The reload looks for the answering mount within the context it is given:
// stopping the stream's owner does not wait for the probe.
func TestReloadProbeForTheAnsweringMountEndsWithItsContext(t *testing.T) {
	for _, name := range []string{"aw run", "wake broker"} {
		t.Run(name, func(t *testing.T) {
			probed := make(chan struct{}, 8)
			release := make(chan struct{})
			hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				probed <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(hanging.Close)
			t.Cleanup(func() { close(release) })
			workingDir, _ := movedMountWorkspace(t, hanging.URL)

			ctx, cancel := context.WithCancel(context.Background())
			returned := make(chan error, 1)
			go func() {
				_, err := answeringMountReloads(workingDir)[name](ctx)
				returned <- err
			}()
			select {
			case <-probed:
			case <-time.After(5 * time.Second):
				t.Fatal("the reload did not probe the server")
			}
			began := time.Now()
			cancel()
			select {
			case err := <-returned:
				if err == nil {
					t.Fatal("a cancelled reload returned an opener")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the reload did not return")
			}
			if waited := time.Since(began); waited > time.Second {
				t.Fatalf("the reload returned %s after its context ended; the probe timeout is %s", waited, awebBaseURLProbeTimeout)
			}
		})
	}
}
