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

// settleWorld is a revoke approved at signedAt in the intent_v1 format, at an
// app at app's origin: the verified frozen intent, the binding pinning the
// team key, the service's applied receipt of the act it issued then, and
// its id, with the request saved as aw saves it.
func settleWorld(t *testing.T, app *ownerActApp, signedAt time.Time) (map[string]any, *handoff.ProfileBinding, *handoff.Receipt, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	key, authority, intent := deliveryWorld(t)
	intent["audience"] = app.server.URL
	const id = "33333333-3333-4333-8333-333333333333"
	body, _ := json.Marshal(intent)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{
		OperationID: id, RequestOrigin: "https://signer.example", HumanOrigin: "https://human.example", Body: body,
	}); err != nil {
		t.Fatal(err)
	}
	act, err := newOwnerAct("human-role.revoke", "h:example.com", app.server.URL, key, intent["subject"].(map[string]any), signedAt)
	if err != nil {
		t.Fatal(err)
	}
	issued := signedAt.UTC().Truncate(time.Second)
	act["expires_at"] = issued.Add(600 * time.Second).Format(time.RFC3339)
	template := map[string]any{}
	for k, v := range act {
		if k != "issued_at" && k != "expires_at" {
			template[k] = v
		}
	}
	frozen := map[string]any{}
	for k, v := range intent {
		frozen[k] = v
	}
	frozen["operation_id"] = id
	frozen["artifact"] = map[string]any{"v": 1, "type": "aweb.protected-artifact-intent", "template": template,
		"delivery":        map[string]any{"audience": app.server.URL, "method": "POST", "path": ownerActDeliveryPath},
		"issuance_window": map[string]any{"not_before": issued.Add(-time.Hour).Format(time.RFC3339), "not_after": issued.Add(23 * time.Hour).Format(time.RFC3339)}}
	raw, _ := json.Marshal(frozen)
	frozen, _ = handoff.DecodeObject(raw)
	signing, signature, err := awid.SignOwnerAct(key, act)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &handoff.Receipt{OperationID: id, State: "committed", Result: producerResult(signing, signature)}
	serviceOwnedReceipt(t, receipt, id)
	binding := &handoff.ProfileBinding{Scope: intent["scope"].(map[string]any), AuthorityKeyDID: authority}
	return frozen, binding, receipt, id
}

// signOnly is receipt's act as a bare signed pair: signed, with no
// confirmation that the app applied it.
func signOnly(t *testing.T, receipt *handoff.Receipt) *handoff.Receipt {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(receipt.Result, &result); err != nil {
		t.Fatal(err)
	}
	pair, _ := json.Marshal(result["artifact"])
	return &handoff.Receipt{OperationID: receipt.OperationID, State: "committed", Result: pair}
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

func TestAnAppliedActForgetsItsSavedRequestAndIsNeverPosted(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, receipt, id := settleWorld(t, app, time.Now())
	if err := settleProtectedAct(settleCommand(), id, frozen, binding, receipt, nil); err != nil {
		t.Fatal(err)
	}
	if len(app.posts) != 0 || saved(t, id) {
		t.Fatalf("posts %d saved %v", len(app.posts), saved(t, id))
	}
}

func TestASignedActWithoutTheServicesApplicationIsNeverPostedAndKeepsItsRequest(t *testing.T) {
	// The service delivers protected acts; a bare signed act is not proof the
	// app applied it, and aw never sends it.
	app := newOwnerActApp(t)
	frozen, binding, receipt, id := settleWorld(t, app, time.Now())
	for range 2 {
		err := settleProtectedAct(settleCommand(), id, frozen, binding, signOnly(t, receipt), nil)
		if errorCodeOf(err) != "application_unconfirmed" || len(app.posts) != 0 || !saved(t, id) {
			t.Fatalf("%v posts %d saved %v", err, len(app.posts), saved(t, id))
		}
	}
}

func TestAnAppliedActThatIsNotTheApprovedIntentIsRefusedAndKeepsItsRequest(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, receipt, id := settleWorld(t, app, time.Now())
	for name, change := range map[string]func(map[string]any){
		"another nonce": func(f map[string]any) {
			f["artifact"].(map[string]any)["template"].(map[string]any)["nonce"] = strings.Repeat("0", 32)
		},
		"issued before its window": func(f map[string]any) {
			f["artifact"].(map[string]any)["issuance_window"].(map[string]any)["not_before"] = time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
		},
	} {
		changed, _ := handoff.DecodeObject(func() []byte { raw, _ := json.Marshal(frozen); return raw }())
		change(changed)
		if err := settleProtectedAct(settleCommand(), id, changed, binding, receipt, nil); errorCodeOf(err) != "signed_act_invalid" || len(app.posts) != 0 || !saved(t, id) {
			t.Errorf("%s: %v posts %d saved %v", name, err, len(app.posts), saved(t, id))
		}
	}
	if err := settleProtectedAct(settleCommand(), id, nil, binding, receipt, nil); errorCodeOf(err) != "signed_act_invalid" || !saved(t, id) {
		t.Errorf("never verified: %v saved %v", err, saved(t, id))
	}
}

func TestAnAppliedActSignedByAnotherKeyIsRefused(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, receipt, id := settleWorld(t, app, time.Now())
	binding.AuthorityKeyDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	if err := settleProtectedAct(settleCommand(), id, frozen, binding, receipt, nil); errorCodeOf(err) != "signed_act_invalid" || len(app.posts) != 0 || !saved(t, id) {
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

// actDelivery is the owner-act route's body for receipt's signed act, as a
// local owner act is delivered.
func actDelivery(t *testing.T, receipt *handoff.Receipt) map[string]any {
	t.Helper()
	var result struct {
		Artifact struct{ Signing, Signature string }
	}
	if err := json.Unmarshal(receipt.Result, &result); err != nil {
		t.Fatal(err)
	}
	signing, _ := base64.StdEncoding.DecodeString(result.Artifact.Signing)
	raw, _ := base64.StdEncoding.DecodeString(result.Artifact.Signature)
	return humanRoleActRequest{Act: "human-role.revoke"}.deliveryBody(signing, base64.RawStdEncoding.EncodeToString(raw))
}

func TestAnAppsRefusalOfADeliveredActCarriesItsCode(t *testing.T) {
	// owner_required is never success, however often the same act is sent.
	app := newOwnerActApp(t)
	app.failWith, app.failCode = http.StatusForbidden, "owner_required"
	_, _, receipt, _ := settleWorld(t, app, time.Now())
	for range 2 {
		if _, err := deliverOwnerAct(settleCommand(), app.server.URL, actDelivery(t, receipt)); errorCodeOf(err) != "owner_required" {
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
		_, _, receipt, _ := settleWorld(t, app, time.Now())
		_, err := deliverOwnerAct(settleCommand(), app.server.URL, actDelivery(t, receipt))
		if err == nil || errors.Is(err, errOwnerActAppliedEarlier) || app.effects != 0 {
			t.Errorf("%d: err %v effects %d", status, err, app.effects)
		}
	}
	app := newOwnerActApp(t)
	_, _, receipt, _ := settleWorld(t, app, time.Now())
	body := actDelivery(t, receipt)
	if _, err := deliverOwnerAct(settleCommand(), app.server.URL, body); err != nil {
		t.Fatal(err)
	}
	if _, err := deliverOwnerAct(settleCommand(), app.server.URL, body); !errors.Is(err, errOwnerActAppliedEarlier) || app.effects != 1 {
		t.Fatalf("the receiver's 409: %v effects %d", err, app.effects)
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

func TestAnOwnerActIsShownOnlyWhenItsIntentNamesThePinnedTeamKey(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, _, _ := settleWorld(t, app, time.Now())
	var kept map[string]any
	if err := ownerActCheck(binding.AuthorityKeyDID, &kept)(context.Background(), frozen); err != nil || kept == nil {
		t.Fatalf("err %v kept %v", err, kept)
	}
	kept = nil
	if err := ownerActCheck("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", &kept)(context.Background(), frozen); errorCodeOf(err) != "operation_mismatch" || kept != nil {
		t.Fatalf("another team key: err %v kept %v", err, kept)
	}
	old, _ := handoff.DecodeObject(func() []byte { raw, _ := json.Marshal(frozen); return raw }())
	delete(old, "approval_format")
	if err := ownerActCheck(binding.AuthorityKeyDID, &kept)(context.Background(), old); err == nil || kept != nil {
		t.Fatalf("no intent format: err %v kept %v", err, kept)
	}
}

// oldRoleSave is settleWorld's request as an older aw saved it: without the
// intent format, under the binding's scope.
func oldRoleSave(t *testing.T, frozen map[string]any, id string) (*awconfig.PendingGovernanceOperation, map[string]any) {
	t.Helper()
	body := map[string]any{}
	for _, name := range []string{"operation", "variant", "scope", "audience", "subject"} {
		body[name] = frozen[name]
	}
	body["operation_id"] = id
	raw, _ := json.Marshal(body)
	decoded, _ := handoff.DecodeObject(raw)
	return &awconfig.PendingGovernanceOperation{OperationID: id, Body: raw}, decoded
}

func TestAnOldAppliedRoleActSettlesOnlyUnderItsOriginalPinnedKey(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, receipt, id := settleWorld(t, app, time.Now().Add(-time.Hour))
	saved, body := oldRoleSave(t, frozen, id)
	profile := &handoff.Profile{Bindings: []handoff.ProfileBinding{*binding}}
	report, facts := roleActReading(profile, time.Now())(saved, body, receipt.Result)
	if report == nil || facts != nil || report["operation_id"] != id || report["applied"] != "service" {
		t.Fatalf("report %v facts %+v", report, facts)
	}
	changed := &handoff.Profile{Bindings: []handoff.ProfileBinding{{Scope: binding.Scope, AuthorityKeyDID: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}}}
	if report, facts := roleActReading(changed, time.Now())(saved, body, receipt.Result); report != nil || facts == nil || facts.Verification != "unverifiable" {
		t.Fatalf("a changed profile key verified history: report %v facts %+v", report, facts)
	}
	if report, facts := roleActReading(&handoff.Profile{}, time.Now())(saved, body, receipt.Result); report != nil || facts == nil {
		t.Fatalf("no original binding verified history: report %v facts %+v", report, facts)
	}
}

func TestAnOldSignedRoleActIsKeptWithItsBytesAndNeverSent(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, receipt, id := settleWorld(t, app, time.Now())
	saved, body := oldRoleSave(t, frozen, id)
	profile := &handoff.Profile{Bindings: []handoff.ProfileBinding{*binding}}
	pair := signOnly(t, receipt).Result
	report, facts := roleActReading(profile, time.Now())(saved, body, pair)
	if report != nil || facts == nil || facts.State != "committed" || facts.Verification != "signature_verified" || len(facts.Signing) == 0 || len(facts.Signature) != 64 {
		t.Fatalf("report %v facts %+v", report, facts)
	}
	if _, facts := roleActReading(profile, time.Now().Add(time.Hour))(saved, body, pair); facts == nil || facts.Verification != "expired" {
		t.Fatalf("an act past its lifetime: %+v", facts)
	}
	other := &handoff.Profile{Bindings: []handoff.ProfileBinding{{Scope: binding.Scope, AuthorityKeyDID: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}}}
	if _, facts := roleActReading(other, time.Now())(saved, body, pair); facts == nil || facts.Verification != "unverifiable" || len(facts.Signing) == 0 {
		t.Fatalf("a signature under another key: %+v", facts)
	}
	if len(app.posts) != 0 {
		t.Fatal("an old signed act was sent")
	}
}

// roleService is a protected service that answers receipts as receipts names
// them and counts every prepare it is sent.
func roleService(t *testing.T) (*receiptService, func(map[string]any) (handoff.GovernanceOptions, bool)) {
	t.Helper()
	service := newReceiptService(t)
	return service, func(scope map[string]any) (handoff.GovernanceOptions, bool) {
		opts, _ := service.reader(scope)
		return opts, true
	}
}

func TestANewRoleActWaitsForAnUnfinishedOldOneForTheSameRole(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, _, id := settleWorld(t, app, time.Now())
	service, optionsFor := roleService(t)
	profile := &handoff.Profile{RequestOrigin: service.server.URL, HumanOrigin: service.server.URL, Bindings: []handoff.ProfileBinding{*binding}}
	saved, _ := oldRoleSave(t, frozen, id)
	saved.RequestOrigin, saved.HumanOrigin = profile.RequestOrigin, profile.HumanOrigin
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	service.receipts[id] = `{"state":"pending","reason":"awaiting_human","expires_at":"2099-01-01T00:00:00Z"}`
	subject := frozen["subject"].(map[string]any)
	err := requestProtectedRoleAct(context.Background(), settleCommand(), profile, binding, optionsFor, "human-role.revoke", app.server.URL, subject, "")
	if errorCodeOf(err) != "operation_reconciliation_required" || service.others != 0 || len(app.posts) != 0 {
		t.Fatalf("err %v others %d posts %d", err, service.others, len(app.posts))
	}
	// --replace with a new --operation-id: only naming the earlier request
	// lets a separately approved one be prepared.
	_ = requestProtectedRoleAct(context.Background(), settleCommand(), profile, binding, optionsFor, "human-role.revoke", app.server.URL, subject, id)
	if service.others != 1 || savedRecord(t, id) == nil {
		t.Fatalf("replace: %d prepares, earlier record kept %v", service.others, savedRecord(t, id) != nil)
	}
}

func TestResumingAnOldRoleActOnlyReadsItsReceipt(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, receipt, id := settleWorld(t, app, time.Now())
	service, optionsFor := roleService(t)
	profile := &handoff.Profile{RequestOrigin: service.server.URL, HumanOrigin: service.server.URL, Bindings: []handoff.ProfileBinding{*binding}}
	saved, _ := oldRoleSave(t, frozen, id)
	saved.RequestOrigin, saved.HumanOrigin = profile.RequestOrigin, profile.HumanOrigin
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	pair, _ := json.Marshal(map[string]any{"state": "committed", "result": json.RawMessage(signOnly(t, receipt).Result)})
	service.receipts[id] = string(pair)
	err := resumeProtectedRoleAct(context.Background(), settleCommand(), profile, saved, optionsFor)
	if errorCodeOf(err) != "operation_reconciliation_required" || service.reads != 1 || service.others != 0 || len(app.posts) != 0 {
		t.Fatalf("err %v reads %d others %d posts %d", err, service.reads, service.others, len(app.posts))
	}
	if q := savedRecord(t, id).Quarantine; q == nil || q.Verification != "signature_verified" {
		t.Fatalf("quarantine %+v", q)
	}
	applied, _ := json.Marshal(map[string]any{"state": "committed", "result": json.RawMessage(receipt.Result)})
	service.receipts[id] = string(applied)
	if err := resumeProtectedRoleAct(context.Background(), settleCommand(), profile, savedRecord(t, id), optionsFor); err != nil || savedRecord(t, id) != nil || service.others != 0 {
		t.Fatalf("applied: err %v others %d", err, service.others)
	}
}

func TestAQuarantinedRoleActIsNeverResumedEvenInTheCurrentFormat(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, _, id := settleWorld(t, app, time.Now())
	service, optionsFor := roleService(t)
	profile := &handoff.Profile{RequestOrigin: service.server.URL, HumanOrigin: service.server.URL, Bindings: []handoff.ProfileBinding{*binding}}
	body := protectedRoleIntent("human-role.revoke", binding.Scope, app.server.URL, frozen["subject"].(map[string]any))
	body["operation_id"] = id
	raw, _ := json.Marshal(body)
	saved := &awconfig.PendingGovernanceOperation{OperationID: id, RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw,
		Quarantine: &awconfig.GovernanceQuarantine{State: "unread", Verification: "unread"}}
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	err := resumeProtectedRoleAct(context.Background(), settleCommand(), profile, saved, optionsFor)
	if errorCodeOf(err) != "operation_reconciliation_required" || service.reads != 1 || service.others != 0 {
		t.Fatalf("err %v reads %d others %d", err, service.reads, service.others)
	}
}
