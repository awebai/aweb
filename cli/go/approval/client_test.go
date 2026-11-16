package approval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	proof "github.com/awebai/approval-service/verify"
)

func cases(t *testing.T, name string) []map[string]any {
	t.Helper()
	raw, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/awebai/approval-service").Output()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(string(bytes.TrimSpace(raw)), "vectors", name+"-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []map[string]any `json:"cases"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	return corpus.Cases
}
func decoded(t *testing.T, s string) []byte {
	t.Helper()
	v, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func num(v any) int64 { n, _ := v.(json.Number).Int64(); return n }
func find(t *testing.T, list []map[string]any, test func(map[string]any) bool) map[string]any {
	t.Helper()
	for _, c := range list {
		if test(c) {
			return c
		}
	}
	t.Fatal("missing pinned seam case")
	return nil
}

func TestRequesterSignsPinnedSubmissionAndPoll(t *testing.T) {
	for _, v := range cases(t, "requester-service") {
		if v["test_signing_seed"] == nil || v["accept"] != true {
			continue
		}
		purpose := v["purpose"].(string)
		if purpose != "submit" && purpose != "poll" {
			continue
		}
		t.Run(v["id"].(string), func(t *testing.T) {
			c := &Client{Origin: v["origin"].(string), Requester: v["expected_requester"].(map[string]any), Key: ed25519.NewKeyFromSeed(decoded(t, v["test_signing_seed"].(string))), Now: func() time.Time { return time.Unix(num(v["signed_at"]), 0) }}
			body := decoded(t, v["body"].(string))
			req, e := c.SignedRequest(t.Context(), purpose, body)
			if e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(req.Body)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, body) || req.URL.Path != v["path"] || req.Method != v["method"] || req.Header.Get("Authorization") != v["authorization"] {
				t.Fatalf("request differs from pinned %s", v["id"])
			}
		})
	}
}

func Test428SessionReadsAnswersAndAssemblesPinnedReceipt(t *testing.T) {
	exchanges := cases(t, "enforcer-requester")
	input := find(t, exchanges, func(v map[string]any) bool { return v["id"] == "needs-human-exact-R" })
	c := &Client{Origin: input["origin"].(string), Requester: input["presenter"].(map[string]any), Now: func() time.Time { return time.Unix(num(input["now"]), 0) }}
	raw, e := proof.Canonical(input["needs_human"])
	if e != nil {
		t.Fatal(e)
	}
	s, e := c.From428(raw, int(num(input["http_status"])))
	if e != nil {
		t.Fatal(e)
	}
	requesterCases := cases(t, "requester-service")
	submitWire := find(t, requesterCases, func(v map[string]any) bool { return v["id"] == "submit-exact-key-and-bytes" })
	submitBody, e := proof.Parse(decoded(t, submitWire["body"].(string)))
	if e != nil {
		t.Fatal(e)
	}
	c.Admission = submitBody["admission"].(map[string]any)
	gotSubmit, e := proof.Canonical(s.Submission())
	if e != nil || !bytes.Equal(gotSubmit, decoded(t, submitWire["body"].(string))) {
		t.Fatal("submission differs from pinned body")
	}
	submitAnswer := find(t, requesterCases, func(v map[string]any) bool { return v["accept"] == true && v["kind"] == "submit" && v["answer"] != nil })
	if _, e = s.ReadAnswer("submit", decoded(t, submitAnswer["answer"].(string)), int(num(submitAnswer["response_status"]))); e != nil {
		t.Fatal(e)
	}
	// An idempotent retry can report an already approved decision, but the
	// closed submit answer is only a summary. C still requires the poll bundle.
	summary, e := proof.Parse(decoded(t, submitAnswer["answer"].(string)))
	if e != nil {
		t.Fatal(e)
	}
	summary["state"] = "approved"
	summaryBytes, e := proof.Canonical(summary)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadAnswer("submit", summaryBytes, 200); e != nil {
		t.Fatal(e)
	}
	if !s.NeedsPoll() {
		t.Fatal("approved submission summary bypassed raw-proof retrieval")
	}
	pollWire := find(t, requesterCases, func(v map[string]any) bool {
		return v["purpose"] == "poll" && v["test_signing_seed"] != nil && v["accept"] == true
	})
	gotPoll, e := proof.Canonical(s.Selection())
	wantPoll, err := proof.Parse(decoded(t, pollWire["body"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	// The independent signing vector uses a different opaque locator; this
	// session must retain the actual locator returned by its submit answer.
	wantPoll["locator"] = s.Locator
	wantPollBytes, err := proof.Canonical(wantPoll)
	if err != nil {
		t.Fatal(err)
	}
	if e != nil || !bytes.Equal(gotPoll, wantPollBytes) {
		t.Fatalf("selection differs from pinned body: %s", gotPoll)
	}
	var assembled bool
	for _, answer := range requesterCases {
		if answer["accept"] != true || answer["kind"] != "poll" || answer["mode"] != "assemble" {
			continue
		}
		original := decoded(t, answer["request_bytes"].(string))
		if !bytes.Equal(original, s.RequestBytes) {
			continue
		}
		if _, e = s.ReadAnswer("poll", decoded(t, answer["answer"].(string)), int(num(answer["response_status"]))); e != nil {
			t.Fatal(e)
		}
		receipt, e := s.Receipt()
		if e != nil {
			t.Fatal(e)
		}
		got, e := proof.Canonical(receipt)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(got, decoded(t, answer["expected_receipt_bytes"].(string))) {
			t.Fatal("receipt differs from exact pinned C")
		}
		presentation, e := s.Presentation()
		if e != nil {
			t.Fatal(e)
		}
		want, e := proof.Canonical(input["presentation"])
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(presentation, want) {
			t.Fatal("enforcer presentation differs from pinned bytes")
		}
		// Assembly is still historical evidence after the live deadline.
		c.Now = func() time.Time { return time.Unix(9999, 0) }
		if _, e = s.Receipt(); e != nil {
			t.Fatalf("deadline erased saved proof: %v", e)
		}
		assembled = true
	}
	if !assembled {
		t.Fatal("no matching pinned approved answer")
	}
}

func TestRequesterResumesRetainedReceiptWithoutService(t *testing.T) {
	input := find(t, cases(t, "enforcer-requester"), func(v map[string]any) bool { return v["id"] == "needs-human-exact-R" })
	c := &Client{Origin: input["origin"].(string), Requester: input["presenter"].(map[string]any), Now: func() time.Time { return time.Unix(num(input["now"]), 0) }}
	presentation := input["presentation"].(map[string]any)
	original := decoded(t, presentation["request_bytes"].(string))
	got, e := c.Resume(t.Context(), original, presentation["receipt"].(map[string]any))
	if e != nil {
		t.Fatal(e)
	}
	want, e := proof.Canonical(presentation)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("resume lost the requester's retained C")
	}
}
