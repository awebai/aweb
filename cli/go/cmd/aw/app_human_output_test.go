package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func decodeJSON(t *testing.T, text string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTerminalOutputTakesEveryMatchAndLeavesTheRest(t *testing.T) {
	response := decodeJSON(t, `{"state":"applied","runner_registrations":[
		{"runner_id":"r1","registration_required":true,"registration_code":"one"},
		{"runner_id":"r2","registration_required":true,"registration_code":"two"}]}`)
	taken, rest := takeTerminalOutput(response, []string{"/runner_registrations/*/registration_code"})
	want := []terminalValue{
		{Pointer: "/runner_registrations/0/registration_code", Value: "one"},
		{Pointer: "/runner_registrations/1/registration_code", Value: "two"},
	}
	if !reflect.DeepEqual(taken, want) {
		t.Fatalf("taken %v", taken)
	}
	wantRest := decodeJSON(t, `{"state":"applied","runner_registrations":[
		{"runner_id":"r1","registration_required":true},
		{"runner_id":"r2","registration_required":true}]}`)
	if !reflect.DeepEqual(rest, wantRest) {
		t.Fatalf("rest %v", rest)
	}
	if registrations := response.(map[string]any)["runner_registrations"].([]any); registrations[0].(map[string]any)["registration_code"] != "one" {
		t.Fatal("the response itself was changed")
	}
}

func TestTerminalOutputThatMatchesNothingTakesNothing(t *testing.T) {
	response := decodeJSON(t, `{"state":"applied","runner_registrations":[]}`)
	taken, rest := takeTerminalOutput(response, []string{"/runner_registrations/*/registration_code", "/absent"})
	if len(taken) != 0 || !reflect.DeepEqual(rest, response) {
		t.Fatalf("taken %v rest %v", taken, rest)
	}
}

func TestTerminalOutputPointersUnescapeTheirSegments(t *testing.T) {
	response := decodeJSON(t, `{"a/b":{"c~d":"secret","keep":1}}`)
	taken, rest := takeTerminalOutput(response, []string{"/a~1b/c~0d"})
	if len(taken) != 1 || taken[0].Value != "secret" || taken[0].Pointer != "/a~1b/c~0d" {
		t.Fatalf("taken %v", taken)
	}
	if !reflect.DeepEqual(rest, decodeJSON(t, `{"a/b":{"keep":1}}`)) {
		t.Fatalf("rest %v", rest)
	}
}
