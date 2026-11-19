package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	proof "github.com/awebai/approval-service/verify"
)

func TestHumanBindingRefreshSanitizesServiceAdvice(t *testing.T) {
	_, err := proof.ReadBindingRefreshAnswer(map[string]any{
		"version": json.Number("1"),
		"error":   map[string]any{"code": "binding_refresh_previous_changed", "message": "Restore\x1b[2J\r\n the last\t binding."},
	}, proof.BindingRefreshAnswerInput{Status: http.StatusConflict})
	if err == nil {
		t.Fatal("shared reader accepted a service refusal")
	}
	err = bindingRefreshAnswerError(err)
	if strings.ContainsAny(err.Error(), "\x1b\r\n\t") || !strings.Contains(err.Error(), "the last binding.") {
		t.Fatalf("unsafe or missing service advice: %q", err.Error())
	}
	var service *proof.ServiceError
	if !errors.As(err, &service) || service.Code != "binding_refresh_previous_changed" || service.HTTPStatus != http.StatusConflict {
		t.Fatalf("lost typed service failure: %v", err)
	}
}

func TestHumanBindingRefreshRejectsMalformedHolderCodes(t *testing.T) {
	for _, code := range []string{"bad\ncode", " bad_code", "Bad_code", "bad-code", "1bad", "bad\x1bcode", strings.Repeat("x", 129)} {
		t.Run(code, func(t *testing.T) {
			raw, err := proof.Canonical(map[string]any{"error": map[string]any{"code": code, "message": "Ask the issuer to check this enrollment."}})
			if err != nil {
				t.Fatal(err)
			}
			err = humanBindingRefreshHolderError(&idRequestExecutionResult{Status: http.StatusConflict, Body: raw})
			if errorCodeOf(err) != "" || !strings.Contains(err.Error(), "Check the person's current ID chain") {
				t.Fatalf("malformed holder code became a public code: %q, %v", errorCodeOf(err), err)
			}
		})
	}
	for _, code := range []string{"binding_refresh_identity_key_changed", "x", "x_1", strings.Repeat("x", 128)} {
		raw, err := proof.Canonical(map[string]any{"error": map[string]any{"code": code, "message": "Ask the issuer to check this enrollment."}})
		if err != nil {
			t.Fatal(err)
		}
		if got := errorCodeOf(humanBindingRefreshHolderError(&idRequestExecutionResult{Status: http.StatusConflict, Body: raw})); got != code {
			t.Fatalf("valid holder code lost: %q", got)
		}
	}
}

func TestHumanBindingRefreshCorruptPacketNamesRetainedSource(t *testing.T) {
	h, binding := refreshBindingFixture(t)
	_, err := readHumanBindingRefreshPacket([]byte("broken"), humanBindingRefreshInput{Human: h, Current: binding, Source: bindingRefreshRetainedReplay})
	if err == nil || strings.Contains(err.Error(), "holder returned") || !strings.Contains(err.Error(), filepath.Join(h.dir, "approval-binding-refresh.json")) {
		t.Fatalf("retained corruption blamed the holder or omitted recovery path: %v", err)
	}
	_, err = readHumanBindingRefreshPacket([]byte("broken"), humanBindingRefreshInput{Human: h, Current: binding, Source: bindingRefreshFromHolder})
	if err == nil || !strings.Contains(err.Error(), "holder returned") {
		t.Fatalf("fresh holder failure lost its source: %v", err)
	}
}

func TestHumanBindingRefreshRecoveryDistinguishesDefinitiveFromUncertain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approval-binding-refresh.json")
	for _, status := range []int{400, 401, 403, 404, 409, 422, 408, 429, 500, 503} {
		_, err := proof.ReadBindingRefreshAnswer(map[string]any{"version": json.Number("1"), "error": map[string]any{"code": "binding_refresh_refused"}}, proof.BindingRefreshAnswerInput{Status: status})
		if err == nil {
			t.Fatal("shared refusal missing")
		}
		got := bindingRefreshRecoveryError(bindingRefreshAnswerError(err), path)
		definitive := status < 500 && status != 408 && status != 429
		if strings.Contains(got.Error(), "remove") != definitive || (definitive && (!strings.Contains(got.Error(), path) || strings.Contains(got.Error(), "Keep the retained packet and retry"))) {
			t.Fatalf("wrong recovery for HTTP %d: %v", status, got)
		}
		var service *proof.ServiceError
		if !errors.As(got, &service) || service.HTTPStatus != status {
			t.Fatalf("lost shared service status %d: %v", status, got)
		}
	}
}
