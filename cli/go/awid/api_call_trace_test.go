package awid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerRequestTraceNamesMethodPathAndStatusOnly(t *testing.T) {
	const secret = "fixture-secret-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"detail":"echo ` + secret + `"}`))
	}))
	defer server.Close()
	send := func() {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/teams/t1/admission-invite?code="+secret, strings.NewReader(`{"token":"`+secret+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := DoServerRequest(&http.Client{}, req, server.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	t.Setenv("AW_TRACE", "1")
	trace := captureStderrForTest(t, send)
	if trace != "AW TRACE call: POST /api/v1/teams/t1/admission-invite -> HTTP 422\n" {
		t.Fatalf("trace=%q", trace)
	}

	t.Setenv("AW_TRACE", "")
	if trace := captureStderrForTest(t, send); trace != "" {
		t.Fatalf("untraced request wrote %q", trace)
	}
}

func TestServerRequestTraceReportsTransportFailureWithoutDetail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	t.Setenv("AW_TRACE", "1")
	trace := captureStderrForTest(t, func() {
		req, err := http.NewRequest(http.MethodGet, url+"/api/v1/cli-auth/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DoServerRequest(&http.Client{}, req, url); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	if trace != "AW TRACE call: GET /api/v1/cli-auth/status -> no response\n" {
		t.Fatalf("trace=%q", trace)
	}
}

func TestServerRequestTraceHidesAttachmentPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	t.Setenv("AW_TRACE", "1")
	trace := captureStderrForTest(t, func() {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/messages/m-1/attachments/a-1", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := DoServerRequest(&http.Client{}, req, server.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	})
	if trace != "AW TRACE call: GET <participant-scoped attachment> -> HTTP 200\n" {
		t.Fatalf("trace=%q", trace)
	}
}
