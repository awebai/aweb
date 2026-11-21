package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestEndedGrantRecoverySurvivesTerminalAndJSONErrorOutput(t *testing.T) {
	const detail = "grant issuing certificate revoked. This grant was issued from a certificate that is no longer current. Ask the issuer for a new grant, or enable renewal on launch and restart the seat if you use OATS."
	body, err := json.Marshal(struct {
		Detail string `json:"detail"`
	}{Detail: detail})
	if err != nil {
		t.Fatal(err)
	}
	refusal := &awid.APIError{StatusCode: http.StatusForbidden, Body: string(body)}
	message := codedRefusalText(refusal, refusal.Error())
	var terminal bytes.Buffer
	writeCLIError(&terminal, message)
	if !strings.Contains(terminal.String(), detail) {
		t.Fatalf("terminal lost the server's recovery instruction: %s", terminal.String())
	}
	var output bytes.Buffer
	if err := writeCLIErrorResult(&output, cliErrorResult{Refusal: refusal, Message: message, JSON: true}); err != nil {
		t.Fatal(err)
	}
	var envelope cliErrorEnvelope
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.HTTPStatus != http.StatusForbidden || envelope.Error.Detail != detail || !strings.Contains(envelope.Error.Message, detail) {
		t.Fatalf("JSON lost the server's refusal or recovery instruction: %+v", envelope.Error)
	}
}
