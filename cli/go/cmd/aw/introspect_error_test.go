package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestWhoamiPreservesInboundModeResourceFailures(t *testing.T) {
	for _, body := range []string{`{"detail":"Agent not found"}`, `{"detail":"private resource"}`, `{}`, `not JSON`} {
		err := &awid.APIError{StatusCode: 404, Body: body}
		if isInboundModeUnsupportedError(err) {
			t.Errorf("resource error hidden as unsupported endpoint: %v", err)
		}
		want := err.Error() + ". Run `aw workspace status` with the same identity home to check the selected team and service."
		if got := formatInboundModeError(err); got != want {
			t.Errorf("inbound mode diagnostic = %q, want %q", got, want)
		}
	}
}

func TestWhoamiRecognizesMissingInboundModeEndpoint(t *testing.T) {
	for _, original := range []*awid.APIError{
		{StatusCode: 404, Body: `{"detail": "Not Found"}`},
		{StatusCode: 405, Body: `{"detail":"Method Not Allowed"}`},
	} {
		if !isInboundModeUnsupportedError(fmt.Errorf("read inbound mode: %w", original)) {
			t.Errorf("missing endpoint not recognized: %v", original)
		}
	}
	if isInboundModeUnsupportedError(fmt.Errorf("network unavailable")) {
		t.Fatal("network failure is not evidence of an unsupported endpoint")
	}
	if !strings.Contains(formatInboundModeError(fmt.Errorf("network unavailable")), "Run `aw workspace status`") {
		t.Fatal("network failure lacks recovery guidance")
	}
}
