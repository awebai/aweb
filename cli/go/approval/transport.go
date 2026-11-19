package approval

import (
	"net/http"

	"github.com/awebai/aw/awid"
)

// HTTPAnswer is bounded transport data before a route-specific answer reader.
// It establishes neither issuer acceptance nor live approval authority.
type HTTPAnswer struct {
	Status int
	Header http.Header
	Body   []byte
}

type approvalHTTPRequest struct {
	Request       *http.Request
	Client        *http.Client
	ResponseLimit int64
}

// Every approval/issuer exchange sends once and returns redirects unchanged.
func sendApprovalRequest(in approvalHTTPRequest) (*HTTPAnswer, error) {
	client := in.Client
	if client == nil {
		client = &http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}
	}
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := bounded.Do(in.Request)
	if err != nil {
		return nil, err
	}
	answer, readErr := awid.ReadAllBounded(response.Body, in.ResponseLimit)
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return &HTTPAnswer{Status: response.StatusCode, Header: response.Header.Clone(), Body: answer}, nil
}
