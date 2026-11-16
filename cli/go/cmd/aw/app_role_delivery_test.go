package main

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type ownerActApp struct {
	server     *httptest.Server
	mu         sync.Mutex
	posts      [][]byte
	effects    int
	applied    map[string]bool
	dropAnswer bool
	failWith   int
	failCode   string
}

func newOwnerActApp(t *testing.T) *ownerActApp {
	app := &ownerActApp{applied: map[string]bool{}}
	app.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.mu.Lock()
		defer app.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		app.posts = append(app.posts, body)
		if r.URL.Path != ownerActDeliveryPath {
			http.NotFound(w, r)
			return
		}
		if app.failWith != 0 {
			w.WriteHeader(app.failWith)
			_, _ = w.Write([]byte(`{"detail":"` + cmp.Or(app.failCode, "unavailable") + `"}`))
			return
		}
		var sent struct{ Signing, Signature string }
		_ = json.Unmarshal(body, &sent)
		// The owner-act contract's canonical signature: 86 unpadded characters.
		if raw, err := base64.RawStdEncoding.Strict().DecodeString(sent.Signature); err != nil || len(raw) != 64 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"detail":"bad_signature"}`))
			return
		}
		// The receiver's exact-act replay acknowledgement (proposed to shared):
		// this act's signing hash already applied.
		if app.applied[sent.Signing] {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"detail":"applied_earlier"}`))
			return
		}
		app.applied[sent.Signing] = true
		app.effects++
		if app.dropAnswer {
			app.dropAnswer = false
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		_, _ = w.Write([]byte(`{"act":"human-role.revoke","principal":"did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn","effective_at":"2099-01-01T00:00:00Z"}`))
	}))
	t.Cleanup(app.server.Close)
	original := ownerActTransport
	ownerActTransport = func() http.RoundTripper { return app.server.Client().Transport }
	t.Cleanup(func() { ownerActTransport = original })
	return app
}

func directOwnerActBody(t *testing.T, origin string) map[string]any {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := newOwnerAct("human-role.revoke", "people:example.com", origin, key,
		map[string]any{"app_id": "example", "installation_id": "00000000-0000-4000-8000-000000000001", "role": "example.owner", "principal": installedChainHuman}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signing, signature, err := awid.SignOwnerAct(key, fields)
	if err != nil {
		t.Fatal(err)
	}
	return humanRoleActRequest{Act: "human-role.revoke"}.deliveryBody(signing, signature)
}

func TestAnAppsRefusalOfADeliveredActCarriesItsCode(t *testing.T) {
	// owner_required is never success, however often the same act is sent.
	app := newOwnerActApp(t)
	app.failWith, app.failCode = http.StatusForbidden, "owner_required"
	body := directOwnerActBody(t, app.server.URL)
	for range 2 {
		if _, err := deliverOwnerAct(&cobra.Command{}, app.server.URL, body); errorCodeOf(err) != "owner_required" {
			t.Fatalf("%v", err)
		}
	}
	if len(app.posts) != 2 || !bytes.Equal(app.posts[0], app.posts[1]) || app.effects != 0 {
		t.Fatalf("posts %d effects %d", len(app.posts), app.effects)
	}
}

func TestOnlyAConflictSayingAppliedEarlierMeansTheActTookEffect(t *testing.T) {
	// applied_earlier means the act took effect only as the receiver's 409.
	// The same words in any other answer, such as an ingress error page or a
	// redirect, are that answer's refusal, with the code.
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable, http.StatusFound, http.StatusBadRequest} {
		app := newOwnerActApp(t)
		app.failWith, app.failCode = status, "applied_earlier"
		body := directOwnerActBody(t, app.server.URL)
		_, err := deliverOwnerAct(&cobra.Command{}, app.server.URL, body)
		if err == nil || errors.Is(err, errOwnerActAppliedEarlier) || app.effects != 0 {
			t.Errorf("%d: err %v effects %d", status, err, app.effects)
		}
	}
	app := newOwnerActApp(t)
	body := directOwnerActBody(t, app.server.URL)
	if _, err := deliverOwnerAct(&cobra.Command{}, app.server.URL, body); err != nil {
		t.Fatal(err)
	}
	if _, err := deliverOwnerAct(&cobra.Command{}, app.server.URL, body); !errors.Is(err, errOwnerActAppliedEarlier) || app.effects != 1 {
		t.Fatalf("the receiver's 409: %v effects %d", err, app.effects)
	}
}
