package awid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAttachmentFetchUsesParticipantAuthAndChecksBytes(t *testing.T) {
	data := []byte("filebytes")
	sum := sha256.Sum256(data)
	descriptor := AttachmentDescriptor{ID: "11111111-1111-4111-8111-111111111111", Filename: "file.pdf", MediaType: "application/pdf", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), ExpiresAt: "2099-01-01T00:00:00Z"}
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	trapCalls := 0
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { trapCalls++; w.Write(data) }))
	defer trap.Close()
	mode := "valid"
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "DIDKey "+did+" ") {
			t.Error("fetch did not use participant identity auth")
		}
		if r.URL.Path != "/v1/messages/22222222-2222-4222-8222-222222222222/attachments/"+descriptor.ID {
			t.Error("fetch escaped message scope")
		}
		if mode == "redirect" {
			http.Redirect(w, r, trap.URL, http.StatusFound)
			return
		}
		if mode == "corrupt" {
			w.Write([]byte("wrong"))
			return
		}
		w.Write(data)
	}))
	defer server.Close()
	client, err := NewWithIdentity(server.URL, key, did)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.FetchAttachment(context.Background(), "mail", "22222222-2222-4222-8222-222222222222", descriptor)
	if err != nil || string(got) != string(data) {
		t.Fatalf("fetch=%q,%v", got, err)
	}
	mode = "corrupt"
	if _, err := client.FetchAttachment(context.Background(), "mail", "22222222-2222-4222-8222-222222222222", descriptor); err == nil {
		t.Fatal("mismatched bytes accepted")
	}
	mode = "redirect"
	if _, err := client.FetchAttachment(context.Background(), "mail", "22222222-2222-4222-8222-222222222222", descriptor); err == nil || trapCalls != 0 {
		t.Fatal("fetch followed a redirect")
	}
	before := calls
	descriptor.Filename = "../x"
	if _, err := client.FetchAttachment(context.Background(), "mail", "22222222-2222-4222-8222-222222222222", descriptor); err == nil || calls != before {
		t.Fatal("invalid descriptor reached transport")
	}
}

func TestAttachmentTraceKeepsNamesAndBytesOutOfLogs(t *testing.T) {
	t.Setenv("AW_TRACE", "1")
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/api/v1/messages/22222222-2222-4222-8222-222222222222/attachments/11111111-1111-4111-8111-111111111111", nil)
	response := &http.Response{Request: request, StatusCode: 200, Header: http.Header{"Content-Disposition": []string{"attachment; filename=PRIVATE_NAME"}}, Body: io.NopCloser(strings.NewReader("PRIVATE_BYTES"))}
	trace := captureStderrForTest(t, func() {
		TraceHTTPRequest(request, nil)
		if err := TraceHTTPResponse(response); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(trace, "PRIVATE_NAME") || strings.Contains(trace, "PRIVATE_BYTES") {
		t.Fatal("attachment content entered trace logs")
	}
	remaining, err := io.ReadAll(response.Body)
	if err != nil || string(remaining) != "PRIVATE_BYTES" {
		t.Fatal("redaction consumed the download")
	}
}
