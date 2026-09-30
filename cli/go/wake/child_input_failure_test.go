package wake

import (
	"context"
	"encoding/json"
	awid "github.com/awebai/aw/awid"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBundledSubmittedFalseUsesBoundedRetryWithoutAcknowledgment(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(filepath.Join(root, "state"))
	attempts := filepath.Join(root, "attempts")
	oats := filepath.Join(root, "oats")
	script := "#!/bin/sh\nif [ \"$1 $2\" = \"session inspect\" ]; then printf '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"idle\"}}\\n'; exit 0; fi\ncat >/dev/null\nprintf x >> " + shellQuoteForTest(attempts) + "\nprintf '{\"ok\":true,\"result\":{\"submitted\":false}}\\n'\n"
	if err := os.WriteFile(oats, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var acks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			acks.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{{"message_id": "mail-false", "from_alias": "bob", "body": "unsubmitted", "created_at": "2026-01-01T00:00:00Z"}}})
	}))
	defer server.Close()
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	reg := Registration{Home: root, IdentityHome: grantHome, Delivery: DeliverySession}
	child := NewChannelCoreRunner(store).StartChild(context.Background(), reg, channelCoreChildConfig{OatsBin: oats, AWCommand: writeFakeAW(t, root, ""), Coalesce: time.Millisecond, RateLimit: time.Millisecond, InspectDelay: time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running })
	child.Offer(reg.ReceiveBindings()[0], awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-false"})
	waitForStatus(t, child, func(st ChannelCoreStatus) bool {
		return st.TraceStage == "lane_job_failed" && strings.Contains(st.LastError, "did not report submitted:true")
	})
	child.Stop()
	data, err := os.ReadFile(attempts)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "xxxx" {
		t.Fatalf("want initial input + 3 bounded retries, got %q", data)
	}
	if acks.Load() != 0 {
		t.Fatalf("unsubmitted mail acknowledged %d times", acks.Load())
	}
	data, _ = os.ReadFile(filepath.Join(grantHome, "channel-delivered-ids-backend_acme.com.json"))
	if strings.Contains(string(data), "mail-false") {
		t.Fatalf("unsubmitted mail marked delivered: %s", data)
	}
}
