package handoff

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// contractCodes are the receipt and HTTP refusal codes the frozen contract
// lists (human-assurance-contract.md section 5).
func contractCodes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../../../docs/human-assurance-contract.md")
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	row := regexp.MustCompile("(?m)^\\| (pending|refused|unknown) \\| (.+) \\|$")
	for _, match := range row.FindAllStringSubmatch(string(raw), -1) {
		for _, code := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(match[2], -1) {
			codes = append(codes, code[1])
		}
	}
	if len(codes) < 25 {
		t.Fatalf("read only %d receipt codes from the contract", len(codes))
	}
	return append(codes, "request_invalid", "redirect_uri_refused", "requester_invalid",
		"scope_refused", "operation_conflict", "operation_not_found",
		"login_rate_limited", "handoff_rate_limited")
}

func TestEveryContractCodeIsTold(t *testing.T) {
	codeLike := regexp.MustCompile(`\b[a-z]+_[a-z_]+\b`)
	for _, code := range contractCodes(t) {
		text := Sentence(code, Facts{})
		if text == "" || !strings.HasSuffix(text, ".") || strings.ToUpper(text[:1]) != text[:1] {
			t.Errorf("%s: %q is not a sentence", code, text)
		}
		if codeLike.MatchString(text) {
			t.Errorf("%s: %q shows a code instead of words", code, text)
		}
	}
}

func TestAnUnknownCodeStillReadsAsASentenceAndNamesTheCode(t *testing.T) {
	text := Sentence("brand_new_code", Facts{})
	if !strings.Contains(text, "brand_new_code") || !strings.HasSuffix(text, ".") {
		t.Fatalf("%q", text)
	}
}

func TestTheAdmissionLimitSaysWhichLimitAndWhatToDoNow(t *testing.T) {
	inZone(t, time.UTC)
	full := Sentence("admission_limit_reached", Facts{Team: "engineering:customer.example",
		Admission: &AdmissionCounts{Active: 5, MaxActive: 5, InWindow: 2, MaxPerWindow: 10}})
	for _, want := range []string{"5 of 5", "engineering:customer.example", "aw id team remove-agent"} {
		if !strings.Contains(full, want) {
			t.Errorf("count limit %q lacks %q", full, want)
		}
	}
	next := time.Date(2026, 11, 13, 14, 40, 0, 0, time.UTC)
	rate := Sentence("admission_limit_reached", Facts{Team: "engineering:customer.example",
		Admission: &AdmissionCounts{Active: 3, MaxActive: 5, InWindow: 10, MaxPerWindow: 10, WindowSeconds: 3600, NextAt: next}})
	for _, want := range []string{"10", "hour", "14:40 UTC"} {
		if !strings.Contains(rate, want) {
			t.Errorf("rate limit %q lacks %q", rate, want)
		}
	}
	if strings.Contains(rate, "remove-agent") {
		t.Errorf("rate limit %q suggests removing an agent, which does not help", rate)
	}
	// Without counts it still says where to look, and promises nothing.
	if bare := Sentence("admission_limit_reached", Facts{}); !strings.Contains(bare, "aw id team admission-policy") {
		t.Errorf("%q", bare)
	}
}

func TestAnExpiryAndARetrySayWhen(t *testing.T) {
	inZone(t, time.UTC)
	at := time.Date(2026, 11, 13, 14, 12, 0, 0, time.UTC)
	if text := Sentence("operation_expired", Facts{ExpiresAt: at}); !strings.Contains(text, "14:12 UTC") {
		t.Errorf("%q", text)
	}
	for _, code := range []string{"login_rate_limited", "handoff_rate_limited", "receipt_unavailable"} {
		if text := Sentence(code, Facts{RetryAt: at}); !strings.Contains(text, "14:12:00 UTC") || strings.Contains(text, code) {
			t.Errorf("%s: %q", code, text)
		}
	}
}

func TestAnUnresolvedOutcomeNamesItsOperationAndForbidsANewOne(t *testing.T) {
	text := Sentence("external_effect_unresolved", Facts{OperationID: "3b1e0000-0000-4000-8000-000000000000"})
	if !strings.Contains(text, "3b1e0000-0000-4000-8000-000000000000") || !strings.Contains(text, "same command") {
		t.Fatalf("%q", text)
	}
}

func TestARefusedReceiptErrsWithItsSentenceAndKeepsItsCode(t *testing.T) {
	err := finalError(&Receipt{OperationID: "op", State: "refused", Code: "human_refused"})
	if ErrorCode(err) != "human_refused" {
		t.Fatalf("code %q", ErrorCode(err))
	}
	if err.Error() != Sentence("human_refused", Facts{}) {
		t.Fatalf("%q", err.Error())
	}
	var coded *Error
	if !errors.As(err, &coded) {
		t.Fatal("not a handoff error")
	}
}

func TestAServiceRefusalErrsWithItsSentence(t *testing.T) {
	err := refusal(403, []byte(`{"detail":"scope_refused"}`))
	if ErrorCode(err) != "scope_refused" || err.Error() != Sentence("scope_refused", Facts{}) {
		t.Fatalf("%q %q", ErrorCode(err), err.Error())
	}
}

func TestAHintedRefusalSaysWhenToTryAgain(t *testing.T) {
	inZone(t, time.UTC)
	at := time.Date(2026, 11, 13, 14, 3, 20, 0, time.UTC)
	defer func(saved func() time.Time) { now = saved }(now)
	now = func() time.Time { return at.Add(-40 * time.Second) }
	resp := &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"40"}}}
	err := hinted(refusal(429, []byte(`{"detail":"handoff_rate_limited"}`)), resp)
	if ErrorCode(err) != "handoff_rate_limited" || !strings.Contains(err.Error(), "14:03:20 UTC") {
		t.Fatalf("%q %q", ErrorCode(err), err.Error())
	}
}

// inZone makes the reader's local zone loc for one test.
func inZone(t *testing.T, loc *time.Location) {
	t.Helper()
	saved := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = saved })
}

// aw tells times in the reader's own zone, named, as the page and the mail do.
func TestTimesReadInTheReadersOwnZone(t *testing.T) {
	inZone(t, time.FixedZone("EST", -5*3600))
	at := time.Date(2026, 11, 13, 14, 12, 0, 0, time.UTC)
	if text := Sentence("operation_expired", Facts{ExpiresAt: at}); !strings.Contains(text, "09:12 EST") || strings.Contains(text, "UTC") {
		t.Errorf("expiry not in the reader's zone: %q", text)
	}
	if text := Sentence("signer_unavailable", Facts{RetryAt: at}); !strings.Contains(text, "09:12:00 EST") || strings.Contains(text, "UTC") {
		t.Errorf("retry time not in the reader's zone: %q", text)
	}
	if got := ReaderTime(at, "2006-01-02 15:04"); got != "2026-11-13 09:12 EST" {
		t.Errorf("ReaderTime = %q", got)
	}
}
