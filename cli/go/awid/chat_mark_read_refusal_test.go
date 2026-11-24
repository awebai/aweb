package awid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// olderServerWatermarkRefusal is FastAPI's validation answer from a server
// released before v1.26.28 to an ids-list read: MarkReadRequest required
// up_to_message_id and forbade other fields (server/src/aweb/routes/chat.py
// at server-v1.8.1 through server-v1.26.24).
const olderServerWatermarkRefusal = `{"detail":[{"type":"missing","loc":["body","up_to_message_id"],"msg":"Field required","input":{"message_ids":["00000000-0000-4000-8000-000000000001"]}},{"type":"extra_forbidden","loc":["body","message_ids"],"msg":"Extra inputs are not permitted","input":["00000000-0000-4000-8000-000000000001"]}]}`

// Every refusal other than the older server's is shown as itself, with no
// watermark retry: a watermark would mark messages read that were never
// presented (Antares d0e3fe47 item 3).
func TestChatMarkReadRetriesOnlyOnTheOlderServersAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "one id unknown", status: http.StatusNotFound, body: `{"detail":"Message not found"}`},
		{name: "forbidden", status: http.StatusForbidden, body: `{"detail":"Not a participant"}`},
		{name: "another validation refusal", status: http.StatusUnprocessableEntity, body: `{"detail":[{"type":"uuid_parsing","loc":["body","message_ids",0],"msg":"Input should be a valid UUID"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveUnadvertisedHealth(w, r) {
					return
				}
				calls++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ChatMarkRead(context.Background(), "session-new", &ChatMarkReadRequest{MessageIDs: chatMarkReadTestIDs()})
			if status, ok := HTTPStatusCode(err); !ok || status != tc.status {
				t.Fatalf("err=%v, want the server's %d", err, tc.status)
			}
			if calls != 1 {
				t.Fatalf("requests=%d, want the exact request only", calls)
			}
		})
	}
}
