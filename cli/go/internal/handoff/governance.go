package handoff

import (
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
// carrying their code. aw never prepares a new operation on its own.
func Approve(ctx context.Context, opts GovernanceOptions, operationID string, intent map[string]any) (*Receipt, error) {
	wake, err := ListenWake()
	if err != nil {
		return nil, err
	}
	defer wake.Close()
	body := map[string]any{"operation_id": operationID, "redirect_uri": wake.RedirectURI()}
	for k, v := range intent {
		body[k] = v
	}
	prepared, err := Prepare(ctx, opts, body)
	if err != nil {
		return nil, err
	}
	wake.Expect(prepared.HandoffID)
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
	go func() {
		if _, err := wake.Wait(waitCtx, prepared.ExpiresAt); err == nil {
			woken <- struct{}{}
		}
	}()
	interval := opts.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for {
		receipt, err := ReadReceipt(ctx, opts, prepared.OperationID)
		if err != nil {
			return nil, err
		}
		switch receipt.State {
		case "committed":
			return receipt, nil
		case "refused", "unknown":
			return receipt, coded(receipt.Code, fmt.Errorf("operation %s is %s: %s", receipt.OperationID, receipt.State, receipt.Code))
		case "pending":
		default:
			return receipt, coded("receipt_invalid", fmt.Errorf("operation %s has an unknown receipt state %q", receipt.OperationID, receipt.State))
		}
		if time.Now().After(prepared.ExpiresAt) {
			return receipt, coded("operation_expired", fmt.Errorf("operation %s was still pending at its expiry", receipt.OperationID))
		}
		select {
		case <-woken:
		case <-time.After(interval):
		case <-ctx.Done():
			return receipt, ctx.Err()
		}
	}
}

// Prepare posts the operation to the request origin and returns it frozen.
// A retry with the same operation id and body returns the original.
func Prepare(ctx context.Context, opts GovernanceOptions, body map[string]any) (*Prepared, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(opts.Request + "/protected-operations")
	if err != nil {
		return nil, err
	}
	resp, err := opts.Sign(ctx, http.MethodPost, target, data)
	if err != nil {
		return nil, err
	}
	reply, err := readReply(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, refusal(resp.StatusCode, reply)
	}
	var prepared Prepared
	if err := json.Unmarshal(reply, &prepared); err != nil || prepared.HandoffID == "" || len(prepared.Digest) != 64 {
		return nil, invalidResult(errors.New("the prepare answer is not a prepared operation"))
	}
	if prepared.OperationID != body["operation_id"] {
		return nil, invalidResult(errors.New("the prepare answer is for another operation"))
	}
	return &prepared, nil
}

// ReadReceipt reads the operation's receipt as its requester.
func ReadReceipt(ctx context.Context, opts GovernanceOptions, operationID string) (*Receipt, error) {
	target, err := url.Parse(opts.Request + "/protected-operations/" + url.PathEscape(operationID))
	if err != nil {
		return nil, err
	}
	resp, err := opts.Sign(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	reply, err := readReply(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, refusal(resp.StatusCode, reply)
	}
	var receipt Receipt
	if err := json.Unmarshal(reply, &receipt); err != nil {
		return nil, invalidResult(err)
	}
	receipt.OperationID = operationID
	return &receipt, nil
}

const approvalRequestDomain = "aweb.approval-request/1\n"

// CoveredRequestDigest is B2's covered-request digest of a frozen approval
// request: lowercase hex SHA-256 of "aweb.approval-request/1" + LF + the
// canonical JSON of covered, the {"policy": {"ref", "version"}, "request"}
// object (human-assurance-contract.md section 5). aw recomputes it, so the
// fingerprint it shows is its own, not the server's.
func CoveredRequestDigest(covered map[string]any) (string, error) {
	canonical, err := awid.CanonicalJSONValue(covered)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(approvalRequestDomain + canonical))
	return hex.EncodeToString(sum[:]), nil
}
