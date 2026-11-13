package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// signedReceipt is a protected service's committed result: the owner act it
// signed with key, in the service's own spelling.
func signedReceipt(t *testing.T, key ed25519.PrivateKey, act, teamID, audience string, subject map[string]any, now time.Time) json.RawMessage {
	t.Helper()
	fields, err := newOwnerAct(act, teamID, audience, key, subject, now)
	if err != nil {
		t.Fatal(err)
	}
	signing, signature, err := awid.SignOwnerAct(key, fields)
	if err != nil {
		t.Fatal(err)
	}
	return producerResult(signing, signature)
}

// producerResult is a committed result as the protected service writes it
// (protected_signer/service.py): both members in padded base64.
func producerResult(signing []byte, signature string) json.RawMessage {
	raw, _ := base64.RawStdEncoding.DecodeString(signature)
	result, _ := json.Marshal(map[string]any{"signing": base64.StdEncoding.EncodeToString(signing), "signature": base64.StdEncoding.EncodeToString(raw)})
	return result
}

func deliveryWorld(t *testing.T) (ed25519.PrivateKey, string, map[string]any) {
	t.Helper()
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	scope := map[string]any{"v": 1, "kind": "protected_key", "service_id": "svc",
		"authority": map[string]any{"kind": "team_controller", "id": "h:example.com", "domain": "example.com"},
		"human":     map[string]any{"id": "did:aw:approver", "domain": "example.com"}, "generation": 1}
	subject := map[string]any{"app_id": "example", "installation_id": "11111111-1111-4111-8111-111111111111", "role": "example.owner", "principal": "did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn"}
	intent := protectedRoleIntent("human-role.revoke", scope, "https://app.example.com", subject)
	return key, awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), intent
}

func TestACommittedActIsTheSignedActAwRequested(t *testing.T) {
	key, authority, intent := deliveryWorld(t)
	now := time.Now()
	result := signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", intent["subject"].(map[string]any), now)
	signed, err := signedActFor(intent, authority, result, now)
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]string
	_ = json.Unmarshal(result, &sent)
	if len(sent["signature"]) != 88 {
		t.Fatalf("the fixture is not the service's padded spelling: %d", len(sent["signature"]))
	}
	raw, _ := base64.StdEncoding.DecodeString(sent["signature"])
	if signed.Act != "human-role.revoke" || signed.Audience != "https://app.example.com" || signed.Signature != base64.RawStdEncoding.EncodeToString(raw) || len(signed.Signature) != 86 {
		t.Fatalf("%+v", signed)
	}
	if want, _ := base64.StdEncoding.DecodeString(sent["signing"]); !bytes.Equal(signed.Signing, want) {
		t.Fatal("the signing bytes changed")
	}
}

func TestASignedActThatIsNotWhatAwRequestedIsNeverDelivered(t *testing.T) {
	key, authority, intent := deliveryWorld(t)
	_, other, _ := awid.GenerateKeypair()
	subject := intent["subject"].(map[string]any)
	otherSubject := map[string]any{"app_id": "example", "installation_id": "11111111-1111-4111-8111-111111111111", "role": "example.owner", "principal": "did:aw:2bLT57MhWjqFm6m4r43K3i8wPZb4"}
	designated := map[string]any{"credential_sha256": strings.Repeat("ab", 32)}
	for k, v := range subject {
		designated[k] = v
	}
	now := time.Now()
	for name, result := range map[string]json.RawMessage{
		"other subject":  signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", otherSubject, now),
		"other audience": signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://evil.example.com", subject, now),
		"other act":      signedReceipt(t, key, "human-role.designate", "h:example.com", "https://app.example.com", designated, now),
		"other team":     signedReceipt(t, key, "human-role.revoke", "x:example.com", "https://app.example.com", subject, now),
		"other key":      signedReceipt(t, other, "human-role.revoke", "h:example.com", "https://app.example.com", subject, now),
		"expired":        signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", subject, now.Add(-time.Hour)),
		"extra member":   json.RawMessage(`{"signing":"AA==","signature":"AA","extra":1}`),
		"duplicate":      json.RawMessage(`{"signing":"AA==","signing":"AA==","signature":"AA"}`),
		"not base64":     json.RawMessage(`{"signing":"%%%","signature":"AA"}`),
		"no signature":   json.RawMessage(`{"signing":"AA=="}`),
		"unpadded signature": func() json.RawMessage {
			r := signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", subject, now)
			var m map[string]string
			_ = json.Unmarshal(r, &m)
			m["signature"] = strings.TrimRight(m["signature"], "=")
			out, _ := json.Marshal(m)
			return out
		}(),
		"short signature": json.RawMessage(`{"signing":"AA==","signature":"` + base64.StdEncoding.EncodeToString(make([]byte, 63)) + `"}`),
		"long signature":  json.RawMessage(`{"signing":"AA==","signature":"` + base64.StdEncoding.EncodeToString(make([]byte, 65)) + `"}`),
		"null":            json.RawMessage(`null`),
		"newline in signature": func() json.RawMessage {
			r := signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", subject, now)
			var m map[string]string
			_ = json.Unmarshal(r, &m)
			m["signature"] = m["signature"][:40] + "\n" + m["signature"][40:]
			out, _ := json.Marshal(m)
			return out
		}(),
		"carriage return in signing": func() json.RawMessage {
			r := signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", subject, now)
			var m map[string]string
			_ = json.Unmarshal(r, &m)
			m["signing"] = m["signing"][:8] + "\r" + m["signing"][8:]
			out, _ := json.Marshal(m)
			return out
		}(),
	} {
		if _, err := signedActFor(intent, authority, result, now); errorCodeOf(err) != "signed_act_invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ownerActApp is an app's owner-act route over TLS: it applies each act once,
// as the app's nonce table does, and can drop its answer after applying.
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

// settleWorld is a committed revoke for an app at app's origin, with its
// request saved as aw saves it.
func settleWorld(t *testing.T, app *ownerActApp, signedAt time.Time) (map[string]any, *handoff.ProfileBinding, *handoff.Receipt, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	key, authority, intent := deliveryWorld(t)
	intent["audience"] = app.server.URL
	result := signedReceipt(t, key, "human-role.revoke", "h:example.com", app.server.URL, intent["subject"].(map[string]any), signedAt)
	const id = "33333333-3333-4333-8333-333333333333"
	body, _ := json.Marshal(intent)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{
		OperationID: id, RequestOrigin: "https://signer.example", HumanOrigin: "https://human.example", Body: body,
	}); err != nil {
		t.Fatal(err)
	}
	binding := &handoff.ProfileBinding{Scope: intent["scope"].(map[string]any), AuthorityKeyDID: authority}
	return intent, binding, &handoff.Receipt{OperationID: id, State: "committed", Result: result}, id
}

func saved(t *testing.T, id string) bool {
	t.Helper()
	op, err := awconfig.LoadPendingGovernanceOperation(id)
	if err != nil {
		t.Fatal(err)
	}
	return op != nil
}

func settleCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetErr(io.Discard)
	cmd.SetContext(context.Background())
	return cmd
}

func TestADeliveredActForgetsItsSavedRequest(t *testing.T) {
	app := newOwnerActApp(t)
	intent, binding, receipt, id := settleWorld(t, app, time.Now())
	if err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil); err != nil {
		t.Fatal(err)
	}
	if len(app.posts) != 1 || app.effects != 1 || saved(t, id) {
		t.Fatalf("posts %d effects %d saved %v", len(app.posts), app.effects, saved(t, id))
	}
}

func TestAFailedDeliveryKeepsTheSavedRequest(t *testing.T) {
	app := newOwnerActApp(t)
	app.failWith = http.StatusServiceUnavailable
	intent, binding, receipt, id := settleWorld(t, app, time.Now())
	err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil)
	if err == nil || !strings.Contains(err.Error(), "resume") || app.effects != 0 || !saved(t, id) {
		t.Fatalf("%v effects %d saved %v", err, app.effects, saved(t, id))
	}
}

func TestALostDeliveryAnswerIsResolvedByDeliveringTheSameActAgainOnce(t *testing.T) {
	app := newOwnerActApp(t)
	app.dropAnswer = true
	intent, binding, receipt, id := settleWorld(t, app, time.Now())
	if err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil); err == nil || !saved(t, id) {
		t.Fatalf("a lost answer settled: %v saved %v", err, saved(t, id))
	}
	// Resume reads the same committed receipt and delivers the same act.
	if err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if app.effects != 1 || len(app.posts) != 2 || !bytes.Equal(app.posts[0], app.posts[1]) || saved(t, id) {
		t.Fatalf("effects %d posts %d same %v saved %v", app.effects, len(app.posts), len(app.posts) == 2 && bytes.Equal(app.posts[0], app.posts[1]), saved(t, id))
	}
}

func TestAnInvalidOrExpiredSignedActIsNeverSent(t *testing.T) {
	app := newOwnerActApp(t)
	intent, binding, receipt, id := settleWorld(t, app, time.Now().Add(-time.Hour))
	err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil)
	if errorCodeOf(err) != "signed_act_invalid" || len(app.posts) != 0 || !saved(t, id) {
		t.Fatalf("%v posts %d saved %v", err, len(app.posts), saved(t, id))
	}
	_, binding, receipt, id = settleWorld(t, app, time.Now())
	binding.AuthorityKeyDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	if err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil); errorCodeOf(err) != "signed_act_invalid" || len(app.posts) != 0 {
		t.Fatalf("another authority key: %v posts %d", err, len(app.posts))
	}
}

func TestARefusedOperationIsForgottenAndNothingIsSent(t *testing.T) {
	app := newOwnerActApp(t)
	intent, binding, _, id := settleWorld(t, app, time.Now())
	refused := &handoff.Receipt{OperationID: id, State: "refused", Code: "human_refused"}
	if err := settleProtectedAct(settleCommand(), id, intent, binding, refused, errors.New("human_refused")); err == nil || len(app.posts) != 0 || saved(t, id) {
		t.Fatalf("%v posts %d saved %v", err, len(app.posts), saved(t, id))
	}
}

func TestAnAppsRefusalKeepsTheSavedRequestWithItsCode(t *testing.T) {
	// owner_required is never success: the same signed act stays saved, and
	// resuming it sends the identical bytes again without re-signing.
	app := newOwnerActApp(t)
	app.failWith, app.failCode = http.StatusForbidden, "owner_required"
	intent, binding, receipt, id := settleWorld(t, app, time.Now())
	for range 2 {
		if err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil); errorCodeOf(err) != "owner_required" || !saved(t, id) {
			t.Fatalf("%v saved %v", err, saved(t, id))
		}
	}
	if len(app.posts) != 2 || !bytes.Equal(app.posts[0], app.posts[1]) || app.effects != 0 {
		t.Fatalf("posts %d effects %d", len(app.posts), app.effects)
	}
}

func TestOnlyAConflictSayingAppliedEarlierSettlesAnOperation(t *testing.T) {
	// applied_earlier means the act took effect only as the receiver's 409.
	// The same words in any other answer, such as an ingress error page or a
	// redirect, leave the act unapplied: its request is kept, with the code.
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable, http.StatusFound, http.StatusBadRequest} {
		app := newOwnerActApp(t)
		app.failWith, app.failCode = status, "applied_earlier"
		intent, binding, receipt, id := settleWorld(t, app, time.Now())
		err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil)
		if err == nil || errorCodeOf(err) != "applied_earlier" || !saved(t, id) || app.effects != 0 {
			t.Errorf("%d: err %v saved %v effects %d", status, err, saved(t, id), app.effects)
		}
	}
}

func serviceOwnedReceipt(t *testing.T, receipt *handoff.Receipt, id string) {
	t.Helper()
	var artifact map[string]string
	if err := json.Unmarshal(receipt.Result, &artifact); err != nil {
		t.Fatal(err)
	}
	signing, _ := base64.StdEncoding.DecodeString(artifact["signing"])
	raw, _ := base64.StdEncoding.DecodeString(artifact["signature"])
	digest, err := awid.ProtectedArtifactDigest(signing, base64.RawStdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	receipt.Result, _ = json.Marshal(map[string]any{"v": 2, "type": "aweb.protected-delivery", "artifact": artifact,
		"delivery": map[string]any{"mode": "service_owned", "state": "applied", "reference": map[string]any{"operation_id": id, "artifact_sha256": digest}}})
}

func TestServiceOwnedAppliedReceiptAfterExpiryNeverPostsAgain(t *testing.T) {
	app := newOwnerActApp(t)
	intent, binding, receipt, id := settleWorld(t, app, time.Now().Add(-time.Hour))
	serviceOwnedReceipt(t, receipt, id)
	if err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil); err != nil {
		t.Fatal(err)
	}
	if len(app.posts) != 0 || app.effects != 0 || saved(t, id) {
		t.Fatalf("posts %d effects %d saved %v", len(app.posts), app.effects, saved(t, id))
	}
}

func TestServiceOwnedReceiptRejectsUnknownModeOrReferenceWithoutLegacyFallback(t *testing.T) {
	for _, dimension := range []string{"mode", "state", "operation_id", "artifact_sha256", "version", "extra"} {
		t.Run(dimension, func(t *testing.T) {
			app := newOwnerActApp(t)
			intent, binding, receipt, id := settleWorld(t, app, time.Now())
			serviceOwnedReceipt(t, receipt, id)
			var result map[string]any
			_ = json.Unmarshal(receipt.Result, &result)
			delivery := result["delivery"].(map[string]any)
			reference := delivery["reference"].(map[string]any)
			switch dimension {
			case "mode":
				delivery["mode"] = "client_owned"
			case "state":
				delivery["state"] = "unknown"
			case "operation_id":
				reference["operation_id"] = "44444444-4444-4444-8444-444444444444"
			case "artifact_sha256":
				reference["artifact_sha256"] = strings.Repeat("0", 64)
			case "version":
				result["v"] = 3
			case "extra":
				result["extra"] = "refuse"
			}
			receipt.Result, _ = json.Marshal(result)
			if err := settleProtectedAct(settleCommand(), id, intent, binding, receipt, nil); errorCodeOf(err) != "signed_act_invalid" {
				t.Fatalf("%v", err)
			}
			if len(app.posts) != 0 || !saved(t, id) {
				t.Fatal("invalid service result posted or forgot original request")
			}
		})
	}
}
