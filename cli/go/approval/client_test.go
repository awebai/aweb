package approval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
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

// Exercise the real HTTPS exchange and shared signed-packet/answer codecs.
// The peer supplies controlled availability responses, not identity evidence.
func TestRequesterPollRetriesKeepOriginalSelectionAndDeadline(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []int
		expired  bool
		want     string
	}{
		{"transient then denied", []int{429, 500, 503, 200}, false, "approval_denied"},
		{"refusal", []int{403}, false, "requester_not_admitted"},
		{"original deadline", []int{503}, true, "request_expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vectors := cases(t, "requester-service")
			wire := find(t, vectors, func(v map[string]any) bool { return v["id"] == "submit-exact-key-and-bytes" })
			body, e := proof.Parse(decoded(t, wire["body"].(string)))
			if e != nil {
				t.Fatal(e)
			}
			original, e := proof.Parse(decoded(t, body["request_bytes"].(string)))
			if e != nil {
				t.Fatal(e)
			}
			var clock atomic.Int64
			clock.Store(time.Now().Unix())
			deadline := clock.Load() + 30
			original["not_before"] = json.Number(strconv.FormatInt(clock.Load()-1, 10))
			original["deadline"] = json.Number(strconv.FormatInt(deadline, 10))
			var c *Client
			var needs map[string]any
			var selection []byte
			var polls int
			peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, e := io.ReadAll(r.Body)
				if e != nil {
					t.Error(e)
					return
				}
				purpose := "poll"
				if r.URL.Path == routes["submit"] {
					purpose = "submit"
				}
				if _, e = proof.CheckHTTP(r.Header.Get("Authorization"), raw, proof.HTTPInput{Requester: c.Requester, Origin: c.Origin, Method: r.Method, Path: r.URL.Path, Purpose: purpose, Now: clock.Load()}); e != nil {
					t.Error(e)
				}
				status := 202
				answer := map[string]any{"version": 1, "digest": needs["digest"], "deadline": deadline, "locator": "request-locator-1", "state": "pending"}
				if purpose == "poll" {
					if selection == nil {
						selection = raw
					} else if !bytes.Equal(raw, selection) {
						t.Error("retry changed original selection")
					}
					if polls >= len(tc.statuses) {
						t.Error("unexpected poll")
						w.WriteHeader(403)
						return
					}
					status = tc.statuses[polls]
					polls++
					if status == 200 {
						answer["state"] = "denied"
						answer["approval"] = nil
					}
					if status >= 400 {
						answer = map[string]any{"version": 1, "error": map[string]any{"code": "requester_not_admitted"}}
					}
					if tc.expired {
						clock.Store(deadline)
					}
				}
				encoded, e := proof.Canonical(answer)
				if e != nil {
					t.Error(e)
					return
				}
				w.WriteHeader(status)
				_, _ = w.Write(encoded)
			}))
			defer peer.Close()
			c = &Client{Origin: peer.URL, Requester: original["requester"].(map[string]any), Key: ed25519.NewKeyFromSeed(decoded(t, wire["test_signing_seed"].(string))), Admission: body["admission"].(map[string]any), HTTP: peer.Client(), Now: func() time.Time { return time.Unix(clock.Load(), 0) }, PollInterval: time.Millisecond, Retain: func(kind string, raw []byte) error { return nil }}
			status, value, e := proof.MakeNeedsHuman(original, c.Origin)
			if e != nil {
				t.Fatal(e)
			}
			needs = value
			raw, e := proof.Canonical(needs)
			if e != nil {
				t.Fatal(e)
			}
			_, e = c.Complete428(context.Background(), raw, status)
			if e == nil || e.Error() != tc.want {
				t.Fatalf("got %v, want %s (polls=%d)", e, tc.want, polls)
			}
			if polls != len(tc.statuses) {
				t.Fatalf("polls %d, want %d", polls, len(tc.statuses))
			}
		})
	}
}
