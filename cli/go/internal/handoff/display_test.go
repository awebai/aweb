package handoff

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

// The request and expectations are the ones naapp-lib's
// test_protected_display_render.py pins for the Python and page renderers,
// so aw says exactly what the page and the owner page say.
func displayRequest(t *testing.T) map[string]any {
	t.Helper()
	request, ok := DecodeObject([]byte(`{"requester":"did:key:z6Mkrequester","subject":{"alias":"agent-one",
		"teams":["a:customer.example","b:customer.example"],"count":3,"nothing":null,
		"policy":{"b":2,"a":[1]},"flag":true}}`))
	if !ok {
		t.Fatal("bad request fixture")
	}
	return request
}

func TestDisplayFillsTemplatesExactlyAsThePageDoes(t *testing.T) {
	display := operationDisplay{
		title:        "Remove {/subject/alias} from {/subject/teams}?",
		consequences: []string{"You answer for it.", "It counts {/subject/count} times."},
		names:        []displayRow{{"member", "/subject/alias"}},
		technical:    []displayRow{{"policy", "/subject/policy"}, {"nothing", "/subject/nothing"}, {"flag", "/subject/flag"}, {"root_key", "/requester"}},
		refusals:     map[string]string{"subject_ineligible": "Not eligible."},
	}
	got, err := display.render(displayRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	want := RenderedDisplay{
		Title:        "Remove agent-one from a:customer.example, b:customer.example?",
		Consequences: []string{"You answer for it.", "It counts 3 times."},
		Names:        [][2]string{{"Member", "agent-one"}},
		Technical:    [][2]string{{"Policy", `{"a":[1],"b":2}`}, {"Nothing", "null"}, {"Flag", "true"}, {"Root key", "did:key:z6Mkrequester"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rendered %#v, want %#v", got, want)
	}
}

func TestDisplayRefusesWhatItCannotFillExactly(t *testing.T) {
	for name, display := range map[string]operationDisplay{
		"missing":          {title: "Remove {/subject/missing}?"},
		"object in title":  {title: "Remove {/subject/policy}?"},
		"null in title":    {title: "Remove {/subject/nothing}?"},
		"bool in title":    {title: "Remove {/subject/flag}?"},
		"object in names":  {title: "Remove it?", names: []displayRow{{"member", "/subject/policy"}}},
		"missing in tech":  {title: "Remove it?", technical: []displayRow{{"member", "/subject/missing"}}},
		"through a string": {title: "Remove it?", technical: []displayRow{{"member", "/subject/alias/deeper"}}},
	} {
		if _, err := display.render(displayRequest(t)); ErrorCode(err) != "operation_mismatch" {
			t.Errorf("%s: rendered without refusing (%v)", name, err)
		}
	}
}

func TestEveryPinnedDefinitionHasItsDisplay(t *testing.T) {
	for selector := range generatedPreparedShapes {
		if display, ok := generatedDisplays[selector]; !ok || display.title == "" {
			t.Errorf("%s has no pinned display", selector)
		}
	}
}

func TestWaitingTextAsksTheDefinitionsQuestion(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt)
	var opened string
	opts := stub.options(&opened)
	opts.NoWait = true
	var text bytes.Buffer
	opts.Notify = &text
	if _, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "Asking the approver: Remove did:aw:holder from example.owner?\n") {
		t.Errorf("the waiting text does not ask the definition's question: %q", text.String())
	}
}

func TestARefusalTheDefinitionNamesReadsAsItsSentence(t *testing.T) {
	stub := newSignerStub(t, `{"state":"refused","code":"subject_ineligible"}`)
	var opened string
	opts := stub.options(&opened)
	opts.Notify = &bytes.Buffer{}
	_, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent())
	if ErrorCode(err) != "subject_ineligible" {
		t.Fatalf("code %q, want subject_ineligible", ErrorCode(err))
	}
	want := "The selected role holding cannot be revoked by this operation."
	if err.Error() != want {
		t.Errorf("refusal reads %q, want the definition's %q", err.Error(), want)
	}
	// Codes the definition does not name keep the shared sentences.
	if got := Sentence("human_refused", Facts{Operation: "human-role.revoke|default"}); got == "" || strings.Contains(got, "role holding") {
		t.Errorf("unexpected shared sentence %q", got)
	}
}
