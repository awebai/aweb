package a2agw

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestA2ABridgeEnvelopeVector pins the v0 inbound bridge envelope against
// docs/vectors/a2a-bridge-envelope-v0.json: semantic section order and JSON
// fields, deliberately not prose wording (docs/a2a.md section 10.1).

type envelopeVectorInput struct {
	TaskID          string `json:"task_id"`
	ContextID       string `json:"context_id"`
	RouteID         string `json:"route_id"`
	TargetAddress   string `json:"target_address"`
	GatewayIdentity string `json:"gateway_identity"`
	CallerScope     string `json:"caller_scope"`
	State           string `json:"state"`
	RequestID       string `json:"request_id"`
	CustomerText    string `json:"customer_text"`
}

type envelopeVectorCase struct {
	Input                   envelopeVectorInput `json:"input"`
	OrderedSectionMarkers   []string            `json:"ordered_section_markers"`
	TaskBlockRequiredFields []string            `json:"task_block_required_fields"`
	TaskBlockExpectedValues map[string]string   `json:"task_block_expected_values"`
	ReplyRequiredFields     []string            `json:"reply_template_required_fields"`
	ReplyExpectedValues     map[string]string   `json:"reply_template_expected_values"`
	ReplyForbiddenFields    []string            `json:"reply_template_forbidden_fields"`
	RequiredPhrases         []string            `json:"required_phrases"`
	CustomerTextMustBeFinal bool                `json:"customer_text_must_be_final_content"`
}

type envelopeVectorFile struct {
	Envelope               envelopeVectorCase `json:"envelope"`
	EnvelopeWithoutContext envelopeVectorCase `json:"envelope_without_context"`
}

func loadEnvelopeVector(t *testing.T) envelopeVectorFile {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "docs", "vectors", "a2a-bridge-envelope-v0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file envelopeVectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

func formatVectorEnvelope(t *testing.T, in envelopeVectorInput) string {
	t.Helper()
	body, err := FormatA2ATaskMessage(a2aTaskEnvelope{
		TaskID:          in.TaskID,
		ContextID:       in.ContextID,
		RouteID:         in.RouteID,
		TargetAddress:   in.TargetAddress,
		GatewayIdentity: in.GatewayIdentity,
		CallerScope:     in.CallerScope,
		State:           in.State,
		RequestID:       in.RequestID,
	}, in.CustomerText)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func fencedJSON(t *testing.T, body, fence string) map[string]any {
	t.Helper()
	block, found := extractFence(body, fence)
	if !found {
		t.Fatalf("envelope missing %s fence:\n%s", fence, body)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(block), &parsed); err != nil {
		t.Fatalf("%s block is not valid JSON: %v\n%s", fence, err, block)
	}
	return parsed
}

func TestA2ABridgeEnvelopeVector(t *testing.T) {
	vec := loadEnvelopeVector(t).Envelope
	body := formatVectorEnvelope(t, vec.Input)

	cursor := 0
	for _, marker := range vec.OrderedSectionMarkers {
		idx := strings.Index(body[cursor:], marker)
		if idx < 0 {
			t.Fatalf("section marker %q missing or out of order:\n%s", marker, body)
		}
		cursor += idx + len(marker)
	}

	task := fencedJSON(t, body, "a2a-task")
	for _, field := range vec.TaskBlockRequiredFields {
		if _, ok := task[field]; !ok {
			t.Fatalf("a2a-task block missing required field %q: %v", field, task)
		}
	}
	for field, want := range vec.TaskBlockExpectedValues {
		if got, _ := task[field].(string); got != want {
			t.Fatalf("a2a-task %s=%q want %q", field, got, want)
		}
	}

	reply := fencedJSON(t, body, "a2a-reply")
	for _, field := range vec.ReplyRequiredFields {
		if _, ok := reply[field]; !ok {
			t.Fatalf("a2a-reply template missing required field %q: %v", field, reply)
		}
	}
	for field, want := range vec.ReplyExpectedValues {
		if got, _ := reply[field].(string); got != want {
			t.Fatalf("a2a-reply template %s=%q want %q", field, got, want)
		}
	}

	for _, phrase := range vec.RequiredPhrases {
		if !strings.Contains(body, phrase) {
			t.Fatalf("envelope missing required phrase %q:\n%s", phrase, body)
		}
	}

	if vec.CustomerTextMustBeFinal && !strings.HasSuffix(strings.TrimSpace(body), strings.TrimSpace(vec.Input.CustomerText)) {
		t.Fatalf("customer text must be the final envelope content:\n%s", body)
	}
}

func TestA2ABridgeEnvelopeVectorWithoutContext(t *testing.T) {
	vec := loadEnvelopeVector(t).EnvelopeWithoutContext
	body := formatVectorEnvelope(t, vec.Input)
	reply := fencedJSON(t, body, "a2a-reply")
	for _, field := range vec.ReplyForbiddenFields {
		if _, ok := reply[field]; ok {
			t.Fatalf("a2a-reply template must omit %q when the task has none: %v", field, reply)
		}
	}
}
