package hookevent

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/strictjson"
)

func TestAnEnvelopeOverTheSizeBoundIsNeverBuilt(t *testing.T) {
	envelope := clientEnvelope()
	envelope["payload"] = map[string]any{"padding": strings.Repeat("a", MaxEnvelopeBytes)}
	if _, err := SigningBytes(envelope); strictjson.Code(err) != "envelope_too_large" {
		t.Fatalf("got %v; want envelope_too_large", err)
	}
}

func TestSigningBytesOverTheSizeBoundAreRefusedBeforeParsing(t *testing.T) {
	hostile := append([]byte(EnvelopePrefix), bytes.Repeat([]byte("["), MaxEnvelopeBytes)...)
	if _, err := Open(hostile); strictjson.Code(err) != "envelope_too_large" {
		t.Fatalf("got %v; want envelope_too_large", err)
	}
}

func TestABodyOverTheDeliveryBoundIsRefusedFirst(t *testing.T) {
	body := bytes.Repeat([]byte(" "), MaxDeliveryBytes+1)
	opts := ReceiveOptions{Audience: "https://logs.example.com", BindingID: "b", Now: time.Now()}
	if _, err := VerifyDelivery("POST", "/hooks/ingest", map[string]string{}, body, opts); strictjson.Code(err) != "request_too_large" {
		t.Fatalf("got %v; want request_too_large", err)
	}
}
