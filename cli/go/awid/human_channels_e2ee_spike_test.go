package awid

// Laboratory reader: no production application imports or advertises this profile.
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type hcXArtifact struct {
	SignedPayload string `json:"signed_payload"`
	Signature     string `json:"signature"`
}
type hcXIdentity struct {
	Seed         string `json:"signing_seed"`
	DID, Address string
	StableID     string                  `json:"stable_id"`
	Private      string                  `json:"x25519_private"`
	Key          *EncryptionKeyAssertion `json:"encryption_key"`
}
type hcXEnvelope struct {
	E2EEMessageEnvelope
	Context map[string]any `json:"group_context"`
}

func (e *hcXEnvelope) UnmarshalJSON(raw []byte) error {
	if err := json.Unmarshal(raw, &e.E2EEMessageEnvelope); err != nil {
		return err
	}
	var wrapper struct {
		Context json.RawMessage `json:"group_context"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return err
	}
	if len(wrapper.Context) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(wrapper.Context))
	decoder.UseNumber()
	return decoder.Decode(&e.Context)
}

type hcXFixture struct {
	BaseURL    string                 `json:"base_url"`
	Owner      string                 `json:"owner"`
	Session    string                 `json:"session_id"`
	Identities map[string]hcXIdentity `json:"identities"`
	Chain      []hcXArtifact          `json:"chain"`
	Original   json.RawMessage        `json:"original"`
	Bridge     hcXEnvelope            `json:"bridge_epoch"`
	Future     hcXEnvelope            `json:"future"`
	Grant      hcXArtifact            `json:"grant"`
	Capsule    E2EEMessageEnvelope    `json:"capsule"`
}

func hcXMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
func hcXCanonical(t *testing.T, v any) []byte {
	t.Helper()
	b, err := StrictCanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func hcXHash(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func hcXUn64(t *testing.T, v string) []byte {
	t.Helper()
	b, err := base64.RawStdEncoding.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func hcXChecked(t *testing.T, a hcXArtifact, signer, schema string) map[string]any {
	t.Helper()
	if err := RequireCanonicalHumanChannelsSignedPayload([]byte(a.SignedPayload)); err != nil {
		t.Fatal(err)
	}
	status, err := VerifySignedPayload(a.SignedPayload, a.Signature, signer, signer)
	if err != nil || status != Verified {
		t.Fatalf("signature %s %v", status, err)
	}
	if schema != "" {
		r, err := DecodeHumanChannelsRecord(schema, []byte(a.SignedPayload))
		if err != nil {
			t.Fatal(err)
		}
		return r.Value
	}
	return hcXMap(t, []byte(a.SignedPayload))
}
func hcXChain(t *testing.T, f hcXFixture) {
	t.Helper()
	previous := "sha256:" + string(bytes.Repeat([]byte("0"), 64))
	for epoch, a := range f.Chain {
		v := hcXChecked(t, a, f.Owner, "MembershipIntent")
		state := v["state"].(map[string]any)
		if v["session_id"] != f.Session || hcNumber(v["epoch"]) != int64(epoch) || v["previous_hash"] != previous || v["signer"] != f.Owner || state["owner"] != f.Owner || (epoch == 0) != (v["operation"] == "create") {
			t.Fatal("chain discontinuity")
		}
		if len(state["delegations"].([]any)) != 0 {
			t.Fatal("outside owner-only experiment")
		}
		commitment := map[string]any{}
		for _, k := range []string{"session_id", "operation_id", "operation", "subjects", "state"} {
			commitment[k] = v[k]
		}
		consents := map[string]any{}
		for _, raw := range v["consents"].([]any) {
			m := raw.(map[string]any)
			artifact := hcXArtifact{m["signed_payload"].(string), m["signature"].(string)}
			untrusted := hcXMap(t, []byte(artifact.SignedPayload))
			subject := untrusted["participant"].(map[string]any)
			c := hcXChecked(t, artifact, subject["did"].(string), "AdmissionConsent")
			if c["policy_hash"] != hcXHash(hcXCanonical(t, commitment)) || c["session_id"] != f.Session || c["operation_id"] != v["operation_id"] || c["membership_hash"] != previous || c["confidentiality"] != state["confidentiality"] || c["signer"] != subject["did"] {
				t.Fatal("consent binding")
			}
			consents[c["consent_id"].(string)] = subject
		}
		for _, raw := range state["members"].([]any) {
			m := raw.(map[string]any)
			if !reflect.DeepEqual(consents[m["consent_id"].(string)], m["participant"]) {
				t.Fatal("missing consent")
			}
		}
		previous = hcXHash([]byte(a.SignedPayload))
	}
}
func hcXLocal(t *testing.T, i hcXIdentity) E2EEDecryptIdentity {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(hcXUn64(t, i.Private))
	if err != nil {
		t.Fatal(err)
	}
	return E2EEDecryptIdentity{Address: i.Address, DID: i.DID, StableID: i.StableID, EncryptionKeyID: i.Key.EncryptionKeyID, PrivateKey: key}
}
func hcXKey(t *testing.T, e *E2EEMessageEnvelope, i hcXIdentity) []byte {
	t.Helper()
	local := hcXLocal(t, i)
	wrap, err := selectE2EEKeyWrap(e, local)
	if err != nil {
		t.Fatal(err)
	}
	cek, err := openE2EEKeyWrap(wrap, e.MessageID, e.ConversationID, e.From, local)
	if err != nil {
		t.Fatal(err)
	}
	return cek
}
func hcXProtected(t *testing.T, e hcXEnvelope, cipher, hashes bool) []byte {
	v := e2eeEnvelopeMap(&e.E2EEMessageEnvelope, false, cipher, hashes)
	v["group_context"] = e.Context
	return hcXCanonical(t, v)
}
func hcXDecrypt(t *testing.T, e hcXEnvelope, cek []byte, managed bool) *E2EEInnerPayload {
	t.Helper()
	cipher := hcXUn64(t, e.Ciphertext)
	if e2eeHashBytes(cipher) != e.Crypto.CiphertextHash || len(cipher) != e.Crypto.CiphertextSize {
		t.Fatal("cipher hash")
	}
	h, err := e2eeHashCanonical("wraps", e2eeKeyWrapsJSONValue(e.KeyWraps))
	if err != nil || h != e.Crypto.KeyWrapsHash {
		t.Fatal("wrap hash")
	}
	aad, err := e2eeContentAAD(&e.E2EEMessageEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if managed {
		aad = hcXProtected(t, e, false, false)
	}
	plain, err := aesGCMOpen(cek, hcXUn64(t, e.Crypto.ContentNonce), cipher, aad)
	if err != nil {
		t.Fatal(err)
	}
	var inner E2EEInnerPayload
	if err = json.Unmarshal(plain, &inner); err != nil {
		t.Fatal(err)
	}
	header := e2eeInnerPayloadMap(inner, false)
	if managed {
		raw := hcXMap(t, plain)
		if !reflect.DeepEqual(raw["group_context"], e.Context) {
			t.Fatal("inner context")
		}
		header["group_context"] = raw["group_context"]
	}
	h, err = e2eeHashCanonical("inner", header)
	if err != nil || h != e.Crypto.InnerHeaderHash {
		t.Fatal("inner hash")
	}
	if !managed {
		if err = verifyE2EEInnerHeader(&e.E2EEMessageEnvelope, &inner); err != nil {
			t.Fatal(err)
		}
	} else if inner.InnerVersion != 3 || inner.MessageID != e.MessageID || inner.ConversationID != e.ConversationID || inner.CreatedAt != e.CreatedAt || inner.From.DID != e.From.DID {
		t.Fatal("inner/outer")
	}
	return &inner
}
func hcXManaged(t *testing.T, e hcXEnvelope, f hcXFixture, epoch int, reader string) *E2EEInnerPayload {
	t.Helper()
	policy := hcXMap(t, []byte(f.Chain[epoch].SignedPayload))
	state := policy["state"].(map[string]any)
	ctx := map[string]any{"session_id": f.Session, "membership_epoch": policy["epoch"], "membership_hash": hcXHash([]byte(f.Chain[epoch].SignedPayload)), "author_ref": map[string]any{"kind": "native", "did": e.From.DID}, "message_id": e.MessageID}
	if !reflect.DeepEqual(ctx, e.Context) || e.MessageVersion != 3 || e.EnvelopeType != "aweb.experimental.managed-chat.x-e2" {
		t.Fatal("managed profile/context")
	}
	status, err := VerifySignedPayload(string(hcXProtected(t, e, true, true)), e.Signature, e.From.DID, e.SigningKeyID)
	if err != nil || status != Verified {
		t.Fatal("managed signature")
	}
	members := map[string]bool{}
	for _, raw := range state["members"].([]any) {
		members[raw.(map[string]any)["participant"].(map[string]any)["did"].(string)] = true
	}
	actual := map[string]bool{e.From.DID: true}
	for _, r := range e.Recipients {
		actual[r.DID] = true
	}
	if !reflect.DeepEqual(members, actual) {
		t.Fatal("recipient policy")
	}
	for _, raw := range state["bridges"].([]any) {
		bridge := raw.(map[string]any)["bridge"]
		found := false
		for _, r := range e.Recipients {
			if r.StableID == bridge {
				found = true
			}
		}
		if !found {
			t.Fatal("missing bridge wrap")
		}
	}
	for _, r := range e.Recipients {
		count := 0
		for _, w := range e.KeyWraps {
			if w.WrapPurpose == "delivery" && w.RecipientDID == r.DID && w.RecipientEncryptionKeyID == r.EncryptionKeyID && w.WrapID == r.WrapID {
				count++
			}
		}
		if count != 1 {
			t.Fatal("missing recipient wrap")
		}
	}
	copies := 0
	for _, w := range e.KeyWraps {
		if w.WrapPurpose == "sender_copy" && w.RecipientDID == e.From.DID {
			copies++
		}
	}
	if copies != 1 {
		t.Fatal("missing sender copy")
	}
	return hcXDecrypt(t, e, hcXKey(t, &e.E2EEMessageEnvelope, f.Identities[reader]), true)
}
func hcXRun(t *testing.T, f hcXFixture) {
	t.Helper()
	hcXChain(t, f)
	originalBytes := hcXCanonical(t, hcXMap(t, f.Original))
	var original E2EEMessageEnvelope
	if err := json.Unmarshal(f.Original, &original); err != nil {
		t.Fatal(err)
	}
	newcomer := hcXLocal(t, f.Identities["carol"])
	if _, err := DecryptE2EEMessage(&original, newcomer); err == nil {
		t.Fatal("newcomer got old key")
	}
	if hcXManaged(t, f.Bridge, f, 1, "bob").Body != "visible to bridge" {
		t.Fatal("bridge body")
	}
	if _, err := DecryptE2EEMessage(&f.Bridge.E2EEMessageEnvelope, newcomer); err == nil {
		t.Fatal("legacy accepted new profile")
	}
	capsule, err := DecryptE2EEMessage(&f.Capsule, newcomer)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Grant         hcXArtifact
		Original, CEK string
	}
	if err = json.Unmarshal([]byte(capsule.Body), &payload); err != nil {
		t.Fatal(err)
	}
	grant := hcXChecked(t, f.Grant, f.Owner, "")
	expected := map[string]any{"version": "aweb.experimental.history-grant.x-e2", "session_id": f.Session, "source_hash": hcXHash(originalBytes), "message_id": original.MessageID, "policy_head": hcXHash([]byte(f.Chain[1].SignedPayload)), "recipient": newcomer.DID, "holder": f.Capsule.From.DID}
	if !reflect.DeepEqual(grant, expected) || payload.Grant != f.Grant || payload.Original != string(originalBytes) {
		t.Fatal("grant/capsule binding")
	}
	if err = VerifyE2EEMessageEnvelopeSignature(&original); err != nil {
		t.Fatal(err)
	}
	cek := hcXUn64(t, payload.CEK)
	if hcXDecrypt(t, hcXEnvelope{E2EEMessageEnvelope: original}, cek, false).Body != "old group content" {
		t.Fatal("original body")
	}
	cek[0] ^= 1
	aad, err := e2eeContentAAD(&original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = aesGCMOpen(cek, hcXUn64(t, original.Crypto.ContentNonce), hcXUn64(t, original.Ciphertext), aad); err == nil {
		t.Fatal("wrong CEK accepted")
	}
	if hcXManaged(t, f.Future, f, 2, "carol").Body != "future after removal" {
		t.Fatal("future body")
	}
	removed := hcXLocal(t, f.Identities["bob"])
	if _, err = selectE2EEKeyWrap(&f.Future.E2EEMessageEnvelope, removed); err == nil {
		t.Fatal("removed member got wrap")
	}
}
func TestHumanChannelsE2EESpikeVector(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/human-channels-e2ee-spike.json")
	if err != nil {
		t.Fatal(err)
	}
	var f hcXFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	hcXRun(t, f)
}
func TestHumanChannelsE2EELiveInput(t *testing.T) {
	path := os.Getenv("AW_TEST_HC_E2EE_SPIKE_FIXTURE")
	if path == "" {
		t.Skip("provided by real HTTP spike")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f hcXFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	bob, err := NewWithIdentity(f.BaseURL, ed25519.NewKeyFromSeed(hcXUn64(t, f.Identities["bob"].Seed)), f.Identities["bob"].DID)
	if err != nil {
		t.Fatal(err)
	}
	carol, err := NewWithIdentity(f.BaseURL, ed25519.NewKeyFromSeed(hcXUn64(t, f.Identities["carol"].Seed)), f.Identities["carol"].DID)
	if err != nil {
		t.Fatal(err)
	}
	var history struct {
		Messages []struct {
			MessageID string          `json:"message_id"`
			Envelope  json.RawMessage `json:"encrypted_envelope"`
		} `json:"messages"`
	}
	pathToHistory := "/v1/chat/sessions/" + f.Session + "/messages"
	if err = bob.Do(context.Background(), "GET", pathToHistory, nil, &history); err != nil {
		t.Fatal(err)
	}
	var original E2EEMessageEnvelope
	if err = json.Unmarshal(f.Original, &original); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, message := range history.Messages {
		if message.MessageID == original.MessageID {
			f.Original = message.Envelope
			found = true
		}
	}
	if !found {
		t.Fatal("Go HTTP client did not receive original")
	}
	if err = carol.Do(context.Background(), "GET", pathToHistory, nil, &history); err == nil {
		t.Fatal("Go newcomer read old room")
	} else if status, ok := HTTPStatusCode(err); !ok || (status != 403 && status != 404) {
		t.Fatal(err)
	}
	var delivered struct {
		Envelope E2EEMessageEnvelope `json:"encrypted_envelope"`
	}
	if err = carol.Do(context.Background(), "GET", "/v1/messages/"+f.Capsule.MessageID, nil, &delivered); err != nil {
		t.Fatal(err)
	}
	f.Capsule = delivered.Envelope
	hcXRun(t, f)
}
