package hookevent

import (
	"bytes"
	"strings"
	"testing"

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
