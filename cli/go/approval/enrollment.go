package approval

import (
	"context"
	"errors"

	proof "github.com/awebai/approval-service/verify"
)

// EnrollmentExchangeInput binds a service exchange to its retained intent and,
// during confirmation, the exact request bytes. It contains no approval stamp.
type EnrollmentExchangeInput struct {
	Purpose      RequestPurpose
	Body         map[string]any
	Intent       map[string]any
	RequestBytes []byte
}

// ExchangeEnrollment uses the one requester transport and shared answer reader.
// A returned confirmation still requires AssembleReceipt before use as evidence.
func (c *Client) ExchangeEnrollment(ctx context.Context, in EnrollmentExchangeInput) (map[string]any, error) {
	switch in.Purpose {
	case PurposeEnrollmentStart, PurposeEnrollmentMaterial, PurposeEnrollmentConfirm, PurposeEnrollmentActivate:
	default:
		return nil, errors.New("Choose a supported enrollment operation before sending this request.")
	}
	raw, status, err := c.exchange(ctx, string(in.Purpose), in.Body)
	if err != nil {
		return nil, err
	}
	return proof.ReadAnswerJSON(string(in.Purpose), raw, proof.AnswerInput{
		Status: status, Intent: in.Intent, RequestBytes: in.RequestBytes,
	})
}
