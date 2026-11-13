package handoff

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Execute runs a bounded unattended operation (human-assurance-contract.md
// section 5) whose exact prepare body is raw, saved by the caller under its
// operation id before this call: it prepares the operation, verifies the
// frozen request is what was sent and passes check, then executes it as the
// requester, with no human page. A repeat with the same bytes is answered
// with the original operation and receipt; nothing is re-signed.
//
// A lost prepare answer is reconciled by its receipt (prepare_unconfirmed
// while pending, to be resumed with the same bytes); a lost execute answer
// likewise, unknown with receipt_unavailable while pending. The prepared
// operation is returned once its answer arrived.
func Execute(ctx context.Context, opts GovernanceOptions, raw []byte, check func(request map[string]any) error) (*Receipt, *Prepared, error) {
	body, ok := decodeObject(raw)
	operationID, _ := body["operation_id"].(string)
	if !ok || operationID == "" {
		return nil, nil, coded("intent_invalid", errors.New("the body is not an operation's"))
	}
	fmt.Fprintf(opts.Notify, "Preparing operation %s\n", operationID)
	// One retry bound for preparing, executing and reconciling a lost answer.
	until := now().Add(retryWithin(opts))
	prepared, err := prepareRetrying(ctx, opts, operationID, body, raw, until)
	if ErrorCode(err) == "prepare_answer_lost" {
		receipt, err := reconcileLostPrepare(ctx, opts, operationID, err, until)
		return receipt, nil, err
	}
	if err != nil {
		return nil, nil, err
	}
	if check != nil {
		payload, _ := decodeObject(prepared.Payload)
		request, _ := payload["request"].(map[string]any)
		if err := check(request); err != nil {
			return nil, prepared, err
		}
	}
	var receipt *Receipt
	err, exhausted := withinBound(ctx, opts, until, func(ctx context.Context) error {
		var err error
		receipt, err = execute(ctx, opts, operationID)
		return err
	})
	switch {
	case ErrorCode(err) == "execute_answer_lost":
		receipt, err = reconcileLostExecute(ctx, opts, operationID, err, until)
		return receipt, prepared, err
	case exhausted:
		return unresolvedReceipt(operationID, "receipt_unavailable"), prepared, coded(ErrorCode(err),
			fmt.Errorf("operation %s could not be executed now (%w); its request is saved, resume it later", operationID, err))
	case err != nil:
		return nil, prepared, err
	case receipt.State == "pending":
		receipt, err = awaitReceipt(ctx, opts, operationID, prepared.ExpiresAt, nil)
		return receipt, prepared, err
	}
	receipt, err = settled(opts, receipt)
	return receipt, prepared, err
}

// execute posts the empty execute request and reads the receipt it answers.
// A transport or read failure is execute_answer_lost: the operation may have
// taken effect, and only its receipt can tell.
func execute(ctx context.Context, opts GovernanceOptions, operationID string) (*Receipt, error) {
	target, err := url.Parse(opts.Request + "/protected-operations/" + url.PathEscape(operationID) + "/execute")
	if err != nil {
		return nil, err
	}
	resp, err := opts.Sign(ctx, http.MethodPost, target, nil)
	if ErrorCode(err) != "" {
		// Refused before anything was sent.
		return nil, err
	}
	if err != nil {
		return nil, coded("execute_answer_lost", err)
	}
	reply, err := readReply(resp)
	if err != nil {
		return nil, coded("execute_answer_lost", err)
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, hinted(coded("receipt_unavailable", refusal(resp.StatusCode, reply)), resp)
	case resp.StatusCode != http.StatusOK:
		return nil, refusal(resp.StatusCode, reply)
	}
	receipt, ok := decodeReceipt(reply)
	if !ok {
		return nil, coded("receipt_invalid", fmt.Errorf("operation %s's execute answer is not a receipt", operationID))
	}
	receipt.OperationID = operationID
	return receipt, nil
}

// reconcileLostExecute reads the receipt of an operation whose execute answer
// never arrived. A final receipt settles it; a pending one is unknown, to be
// resumed with the same saved bytes, never executed again here.
func reconcileLostExecute(ctx context.Context, opts GovernanceOptions, operationID string, lost error, until time.Time) (*Receipt, error) {
	var receipt *Receipt
	err, _ := withinBound(ctx, opts, until, func(ctx context.Context) error {
		var err error
		receipt, err = ReadReceipt(ctx, opts, operationID)
		return err
	})
	if err != nil {
		return unresolvedReceipt(operationID, "receipt_unavailable"),
			coded("receipt_unavailable", fmt.Errorf("operation %s: %v, and its receipt could not be read: %w", operationID, lost, err))
	}
	if receipt.State == "pending" {
		return unresolvedReceipt(operationID, "receipt_unavailable"),
			coded("receipt_unavailable", fmt.Errorf("operation %s's execute answer was lost and it is still pending; resume it with the same operation id", operationID))
	}
	return settled(opts, receipt)
}
