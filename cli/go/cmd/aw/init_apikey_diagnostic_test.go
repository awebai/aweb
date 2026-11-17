package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestWorkspaceInitDiagnosticReadsRequestIDBesideAStringDetail(t *testing.T) {
	const requestID = "11111111-2222-4333-8444-555555555555"
	for name, body := range map[string]string{
		"string detail": `{"detail":"Team creator must sign this request","request_id":"` + requestID + `"}`,
		"list detail":   `{"detail":[{"loc":["body","did"],"msg":"field required"}],"request_id":"` + requestID + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}}
			got := workspaceInitHTTPDiagnostic(resp, []byte(body), "")
			if !strings.Contains(got, "request_id="+requestID) {
				t.Fatalf("request_id lost: %s", got)
			}
			if strings.Contains(got, "creator must sign") || strings.Contains(got, "field required") {
				t.Fatalf("server text echoed: %s", got)
			}
		})
	}
}
