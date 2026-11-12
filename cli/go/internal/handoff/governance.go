package handoff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/awebai/aw/awid"
)

// GovernanceOptions configure one protected operation: the protected
// service's pinned request and human origins (from its provisioned profile,
// never from a response) and the restricted requester's signer.
type GovernanceOptions struct {
	Request string
	Human   string
	// Sign sends a request to Request as the restricted requester.
	Sign   Signer
	Open   func(url string) error
	Notify io.Writer
	// PollInterval bounds how often the receipt is read without a wake.
	PollInterval time.Duration
	// Save persists an operation's exact prepare body before it is sent, so a
	// lost answer can be resumed with Resume under the same id and binding.
	Save func(operationID string, body []byte) error
	// Forget drops what Save kept once a receipt is final: committed or
	// refused. A pending, unknown, lost or expired operation stays saved.
	Forget func(operationID string) error
}

// Prepared is a prepared protected operation: the frozen request the human
// approves, identified by an id aw chose before preparing it.
type Prepared struct {
	OperationID string          `json:"operation_id"`
	HandoffID   string          `json:"handoff_id"`
	Digest      string          `json:"digest"`
	Payload     json.RawMessage `json:"payload"`
	ExpiresAt   time.Time       `json:"expires_at"`
}

// Receipt is a protected operation's outcome. Only a receipt establishes
// that an operation committed (human-assurance-contract.md section 5).
type Receipt struct {
	OperationID string          `json:"-"`
	State       string          `json:"state"`
	Reason      string          `json:"reason,omitempty"`
	Code        string          `json:"code,omitempty"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
}

// Fingerprint is the comparison aid shown beside a full digest: its first 16
// hex characters in four groups of four.
func Fingerprint(digest string) string {
	if len(digest) < 16 {
		return ""
	}
	return digest[0:4] + " " + digest[4:8] + " " + digest[8:12] + " " + digest[12:16]
}

// Approve prepares the operation under operationID, shows its digest, opens
// the protected service's page for the human's exact-act approval, and reads
// the receipt until it is final. A browser return only wakes aw sooner.
// committed returns the receipt; refused and unknown return it with an error
// carrying their code. aw never prepares a new operation on its own: when the
// prepare answer is lost it reconciles through the receipt of the same id,
// and the saved body resumes it (Resume).
func Approve(ctx context.Context, opts GovernanceOptions, operationID string, intent map[string]any) (*Receipt, error) {
	for _, reserved := range []string{"operation_id", "redirect_uri"} {
		if _, ok := intent[reserved]; ok {
			return nil, coded("intent_invalid", fmt.Errorf("the intent names %s, which aw sets", reserved))
		}
	}
	wake, err := ListenWake()
	if err != nil {
		return nil, err
	}
	defer wake.Close()
	members := map[string]any{}
	for k, v := range intent {
		members[k] = v
	}
	members["operation_id"] = operationID
	members["redirect_uri"] = wake.RedirectURI()
	raw, err := json.Marshal(members)
	if err != nil {
		return nil, coded("intent_invalid", err)
	}
	// The body as it decodes from its bytes, the same on a resume.
	body, ok := decodeObject(raw)
	if !ok {
		return nil, coded("intent_invalid", errors.New("the intent is not a JSON object"))
	}
	if opts.Save != nil {
		if err := opts.Save(operationID, raw); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(opts.Notify, "Preparing operation %s\n", operationID)
	return approve(ctx, opts, operationID, body, raw, wake)
}

// Resume sends a saved prepare body again, byte for byte: the protected
// service answers a repeat of the same id and body with the original
// operation, which is verified and approved as Approve does. The saved
// redirect_uri's loopback is gone, so only the receipt is read.
func Resume(ctx context.Context, opts GovernanceOptions, saved []byte) (*Receipt, error) {
	body, ok := decodeObject(saved)
	operationID, _ := body["operation_id"].(string)
	if !ok || operationID == "" {
		return nil, coded("intent_invalid", errors.New("the saved body is not a prepared operation's"))
	}
	fmt.Fprintf(opts.Notify, "Resuming operation %s\n", operationID)
	return approve(ctx, opts, operationID, body, saved, nil)
}

func approve(ctx context.Context, opts GovernanceOptions, operationID string, body map[string]any, raw []byte, wake *Loopback) (*Receipt, error) {
	prepared, err := prepare(ctx, opts, body, raw)
	if ErrorCode(err) == "prepare_answer_lost" {
		return reconcileLostPrepare(ctx, opts, operationID, err)
	}
	if err != nil {
		return nil, err
	}
	page := opts.Human + "/handoff/" + url.PathEscape(prepared.HandoffID)
	fmt.Fprintf(opts.Notify, "Operation %s\n  digest:      %s\n  fingerprint: %s\nApprove it on this page: %s\n",
		prepared.OperationID, prepared.Digest, Fingerprint(prepared.Digest), page)
	if opts.Open != nil {
		if err := opts.Open(page); err != nil {
			fmt.Fprintf(opts.Notify, "Could not open a browser (%v); open the page above yourself.\n", err)
		}
	}
	woken := make(chan struct{}, 1)
	waitCtx, stop := context.WithCancel(ctx)
	defer stop()
	if wake != nil {
		wake.Expect(prepared.HandoffID)
		go func() {
			if _, err := wake.Wait(waitCtx, prepared.ExpiresAt); err == nil {
				woken <- struct{}{}
			}
		}()
	}
	interval := opts.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for {
		receipt, err := ReadReceipt(ctx, opts, operationID)
		switch {
		case ErrorCode(err) == "receipt_unavailable":
			// Read again until the operation expires; the outcome stays unknown.
			if time.Now().After(prepared.ExpiresAt) {
				return unresolvedReceipt(operationID, "receipt_unavailable"), err
			}
		case err != nil:
			return unresolvedReceipt(operationID, ErrorCode(err)), err
		case receipt.State != "pending":
			return settled(opts, receipt)
		case time.Now().After(prepared.ExpiresAt):
			return receipt, coded("operation_expired", fmt.Errorf("operation %s was still pending at its expiry", operationID))
		}
		select {
		case <-woken:
		case <-time.After(interval):
		case <-ctx.Done():
			return unresolvedReceipt(operationID, "receipt_unavailable"), ctx.Err()
		}
	}
}

// reconcileLostPrepare reads the receipt of an operation whose prepare answer
// never arrived. A pending operation cannot be shown without its frozen
// request, so aw reports it under its id, to be resumed from its saved body.
func reconcileLostPrepare(ctx context.Context, opts GovernanceOptions, operationID string, lost error) (*Receipt, error) {
	receipt, err := ReadReceipt(ctx, opts, operationID)
	if err != nil {
		return unresolvedReceipt(operationID, "receipt_unavailable"),
			coded("receipt_unavailable", fmt.Errorf("operation %s: %v, and its receipt could not be read: %w", operationID, lost, err))
	}
	if receipt.State == "pending" {
		return receipt, coded("prepare_unconfirmed", fmt.Errorf("operation %s is pending but its prepare answer was lost; resume it from its saved request", operationID))
	}
	return settled(opts, receipt)
}

// settled returns a receipt that is no longer pending, forgetting the saved
// operation when its outcome is final. A failure to forget leaves a stale
// saved body behind; it does not change the outcome.
func settled(opts GovernanceOptions, receipt *Receipt) (*Receipt, error) {
	if opts.Forget != nil && (receipt.State == "committed" || receipt.State == "refused") {
		if err := opts.Forget(receipt.OperationID); err != nil {
			fmt.Fprintf(opts.Notify, "Operation %s is %s, but its saved request could not be removed: %v\n", receipt.OperationID, receipt.State, err)
		}
	}
	return receipt, finalError(receipt)
}

// finalError is nil for a committed receipt and carries a refused or unknown
// receipt's code otherwise.
func finalError(receipt *Receipt) error {
	if receipt.State == "committed" {
		return nil
	}
	return coded(receipt.Code, fmt.Errorf("operation %s is %s: %s", receipt.OperationID, receipt.State, receipt.Code))
}

func unresolvedReceipt(operationID, code string) *Receipt {
	return &Receipt{OperationID: operationID, State: "unknown", Code: code}
}

// preparedMembers and artifactMembers are the closed member sets of the
// prepare answer and of the artifact it freezes (human-assurance-contract.md
// section 5).
var (
	preparedMembers = []string{"operation_id", "handoff_id", "digest", "payload", "expires_at"}
	artifactMembers = []string{"v", "type", "act", "team_id", "team_key_did", "aud", "subject", "nonce", "issued_at", "expires_at"}
)

// Prepare posts the operation to the request origin and returns it frozen.
// A retry with the same operation id and body returns the original. When the
// answer is lost in transit the error is prepare_answer_lost: the operation
// may exist, and only its receipt can tell.
func Prepare(ctx context.Context, opts GovernanceOptions, body map[string]any) (*Prepared, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return prepare(ctx, opts, body, data)
}

// prepare sends data, the exact bytes of body, and verifies the answer
// against body.
func prepare(ctx context.Context, opts GovernanceOptions, body map[string]any, data []byte) (*Prepared, error) {
	target, err := url.Parse(opts.Request + "/protected-operations")
	if err != nil {
		return nil, err
	}
	resp, err := opts.Sign(ctx, http.MethodPost, target, data)
	if err != nil {
		return nil, coded("prepare_answer_lost", err)
	}
	reply, err := readReply(resp)
	if err != nil {
		return nil, coded("prepare_answer_lost", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, refusal(resp.StatusCode, reply)
	}
	answer, ok := decodeObject(reply)
	if !ok || !exactMembers(answer, preparedMembers) {
		return nil, invalidResult(errors.New("the prepare answer is not a prepared operation"))
	}
	prepared := Prepared{}
	prepared.OperationID, _ = answer["operation_id"].(string)
	prepared.HandoffID, _ = answer["handoff_id"].(string)
	prepared.Digest, _ = answer["digest"].(string)
	expires, _ := answer["expires_at"].(string)
	prepared.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	payload, isObject := answer["payload"].(map[string]any)
	if prepared.HandoffID == "" || err != nil || !isObject {
		return nil, invalidResult(errors.New("the prepare answer is not a prepared operation"))
	}
	if prepared.OperationID != body["operation_id"] {
		return nil, invalidResult(errors.New("the prepare answer is for another operation"))
	}
	if err := verifyPrepared(body, prepared.Digest, payload); err != nil {
		return nil, err
	}
	prepared.Payload, _ = awid.StrictCanonicalJSON(payload)
	return &prepared, nil
}

// serverAddedMembers are the only members the protected service adds to the
// frozen request beside what aw sent, and it adds all of them
// (human-assurance-contract.md section 5).
var serverAddedMembers = []string{"requester", "policy_ref", "policy_version", "artifact"}

// verifyPrepared recomputes the digest from the frozen payload and requires
// that the payload carries exactly what aw sent, so the digest and
// fingerprint aw shows are its own and the page must match them.
func verifyPrepared(sent map[string]any, digest string, payload map[string]any) error {
	mismatch := func(reason string) error {
		return coded("operation_mismatch", fmt.Errorf("the prepared operation is not what aw sent: %s", reason))
	}
	policy, _ := payload["policy"].(map[string]any)
	request, _ := payload["request"].(map[string]any)
	if !exactMembers(payload, []string{"policy", "request"}) || policy == nil || request == nil ||
		!exactMembers(policy, []string{"ref", "version"}) {
		return mismatch("the payload is not a covered request")
	}
	recomputed, err := CoveredRequestDigest(payload)
	if err != nil || recomputed != digest {
		return mismatch("its digest does not match its payload")
	}
	expected := append([]string{}, serverAddedMembers...)
	for name, value := range sent {
		if !sameJSON(request[name], value) {
			return mismatch("its " + name + " differs")
		}
		expected = append(expected, name)
	}
	if !exactMembers(request, expected) {
		return mismatch("it adds or omits a member")
	}
	if _, ok := request["requester"].(string); !ok {
		return mismatch("it names no requester")
	}
	if !sameJSON(request["policy_ref"], policy["ref"]) || !sameJSON(request["policy_version"], policy["version"]) {
		return mismatch("its policy differs from its request")
	}
	// The artifact is what gets signed: its act, team, subject and audience
	// are exactly what aw asked for.
	artifact, _ := request["artifact"].(map[string]any)
	if artifact == nil || !exactMembers(artifact, artifactMembers) || artifact["type"] != "aweb.owner-act" {
		return mismatch("its artifact is not an owner act")
	}
	scope, _ := sent["scope"].(map[string]any)
	authority, _ := scope["authority"].(map[string]any)
	if !sameJSON(artifact["act"], sent["operation"]) || !sameJSON(artifact["team_id"], authority["id"]) {
		return mismatch("its artifact is for another act or team")
	}
	if !sameJSON(artifact["subject"], sent["subject"]) || !sameJSON(artifact["aud"], sent["audience"]) {
		return mismatch("its artifact names another subject or audience")
	}
	return nil
}

// exactMembers reports whether object has exactly the named members.
func exactMembers(object map[string]any, names []string) bool {
	if len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return false
		}
	}
	return true
}

// sameJSON compares two JSON values by their strict canonical encoding.
func sameJSON(a, b any) bool {
	left, err := awid.StrictCanonicalJSON(a)
	if err != nil {
		return false
	}
	right, err := awid.StrictCanonicalJSON(b)
	return err == nil && bytes.Equal(left, right)
}

// ReadReceipt reads the operation's receipt as its requester. A receipt that
// cannot be read now (transport, 429, 5xx) is receipt_unavailable; any other
// refusal keeps its own code; one that is not exactly a receipt of its state
// is receipt_invalid.
func ReadReceipt(ctx context.Context, opts GovernanceOptions, operationID string) (*Receipt, error) {
	target, err := url.Parse(opts.Request + "/protected-operations/" + url.PathEscape(operationID))
	if err != nil {
		return nil, err
	}
	unavailable := func(err error) error {
		return coded("receipt_unavailable", fmt.Errorf("the receipt of operation %s could not be read: %w", operationID, err))
	}
	resp, err := opts.Sign(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, unavailable(err)
	}
	reply, err := readReply(resp)
	if err != nil {
		return nil, unavailable(err)
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, unavailable(refusal(resp.StatusCode, reply))
	case resp.StatusCode != http.StatusOK:
		// A refusal of the requester, its scope or the id does not pass.
		return nil, refusal(resp.StatusCode, reply)
	}
	receipt, ok := decodeReceipt(reply)
	if !ok {
		return nil, coded("receipt_invalid", fmt.Errorf("operation %s has no valid receipt", operationID))
	}
	receipt.OperationID = operationID
	return receipt, nil
}

// decodeReceipt accepts exactly the receipt shape of its state.
func decodeReceipt(reply []byte) (*Receipt, bool) {
	object, ok := decodeObject(reply)
	if !ok {
		return nil, false
	}
	state, _ := object["state"].(string)
	receipt := &Receipt{State: state}
	switch state {
	case "pending":
		receipt.Reason, _ = object["reason"].(string)
		text, _ := object["expires_at"].(string)
		expires, err := time.Parse(time.RFC3339Nano, text)
		if !exactMembers(object, []string{"state", "reason", "expires_at"}) || receipt.Reason == "" || err != nil {
			return nil, false
		}
		receipt.ExpiresAt = &expires
	case "committed":
		result, isObject := object["result"].(map[string]any)
		if !exactMembers(object, []string{"state", "result"}) || !isObject {
			return nil, false
		}
		canonical, err := awid.StrictCanonicalJSON(result)
		if err != nil {
			return nil, false
		}
		receipt.Result = canonical
	case "refused", "unknown":
		receipt.Code, _ = object["code"].(string)
		if !exactMembers(object, []string{"state", "code"}) || receipt.Code == "" {
			return nil, false
		}
	default:
		return nil, false
	}
	return receipt, true
}

// DecodeObject decodes exactly one JSON object, numbers as json.Number,
// refusing duplicate members at any depth, so what aw checks is what any other
// reader of the bytes sees.
func DecodeObject(raw []byte) (map[string]any, bool) {
	return decodeObject(raw)
}

func decodeObject(raw []byte) (map[string]any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	object, ok := value.(map[string]any)
	return object, ok
}

const maxJSONDepth = 64

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name := key.(string)
			if _, seen := object[name]; seen {
				return nil, errors.New("duplicate member " + name)
			}
			if object[name], err = decodeValue(decoder, depth+1); err != nil {
				return nil, err
			}
		}
		_, err := decoder.Token()
		return object, err
	case '[':
		array := []any{}
		for decoder.More() {
			item, err := decodeValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, item)
		}
		_, err := decoder.Token()
		return array, err
	}
	return nil, errors.New("unexpected delimiter")
}

const approvalRequestDomain = "aweb.approval-request/1\n"

// CoveredRequestDigest is B2's covered-request digest of a frozen approval
// request: lowercase hex SHA-256 of "aweb.approval-request/1" + LF + the
// strict canonical JSON of covered, the {"policy": {"ref", "version"},
// "request"} object (human-assurance-contract.md section 5). aw recomputes
// it, so the fingerprint it shows is its own, not the server's.
func CoveredRequestDigest(covered map[string]any) (string, error) {
	canonical, err := awid.StrictCanonicalJSON(covered)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(approvalRequestDomain), canonical...))
	return hex.EncodeToString(sum[:]), nil
}
