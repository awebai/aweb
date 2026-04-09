package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendControlSignal(t *testing.T) {
	t.Parallel()

	var gotAuth string
	var gotPath string
	var gotReq SendControlSignalRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(SendControlSignalResponse{
			SignalID: "sig-1",
			Signal:   ControlSignalPause,
		})
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.SendControlSignal(context.Background(), "alice", ControlSignalPause)
	if err != nil {
		t.Fatalf("SendControlSignal returned error: %v", err)
	}
	if gotAuth != "" {
		t.Fatalf("auth=%q", gotAuth)
	}
	if gotPath != "/v1/agents/alice/control" {
		t.Fatalf("path=%q", gotPath)
	}
	if gotReq.Signal != ControlSignalPause {
		t.Fatalf("signal=%q", gotReq.Signal)
	}
	if resp.SignalID != "sig-1" || resp.Signal != ControlSignalPause {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestSendControlSignalValidatesInputs(t *testing.T) {
	t.Parallel()

	client, err := New("http://example.com")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.SendControlSignal(context.Background(), "", ControlSignalPause); err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("expected alias validation error, got %v", err)
	}
	if _, err := client.SendControlSignal(context.Background(), "alice", ControlSignal("bogus")); err == nil || !strings.Contains(err.Error(), "invalid control signal") {
		t.Fatalf("expected signal validation error, got %v", err)
	}
}

func TestPauseResumeInterruptAgentWrappers(t *testing.T) {
	t.Parallel()

	var gotSignals []ControlSignal
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req SendControlSignalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		gotSignals = append(gotSignals, req.Signal)
		_ = json.NewEncoder(w).Encode(SendControlSignalResponse{
			SignalID: "sig",
			Signal:   req.Signal,
		})
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.PauseAgent(context.Background(), "alice"); err != nil {
		t.Fatalf("PauseAgent returned error: %v", err)
	}
	if _, err := client.ResumeAgent(context.Background(), "alice"); err != nil {
		t.Fatalf("ResumeAgent returned error: %v", err)
	}
	if _, err := client.InterruptAgent(context.Background(), "alice"); err != nil {
		t.Fatalf("InterruptAgent returned error: %v", err)
	}

	want := []ControlSignal{ControlSignalPause, ControlSignalResume, ControlSignalInterrupt}
	if len(gotSignals) != len(want) {
		t.Fatalf("signals=%v", gotSignals)
	}
	for i := range want {
		if gotSignals[i] != want[i] {
			t.Fatalf("signals=%v", gotSignals)
		}
	}
}

func TestSendControlSignalHTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"Agent not found"}`, http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.SendControlSignal(context.Background(), "alice", ControlSignalPause)
	if err == nil {
		t.Fatal("expected error")
	}
	code, ok := HTTPStatusCode(err)
	if !ok || code != http.StatusNotFound {
		t.Fatalf("expected 404 api error, got %v", err)
	}
}
