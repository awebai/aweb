package wake

import (
	"context"
	"strings"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

func TestChannelCoreRunnerReportsMissingSystemNode(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := NewChannelCoreRunner(store)
	t.Setenv("PATH", "")
	_, err = runner.Deliver(context.Background(), Registration{Home: t.TempDir()}, ReceiveIdentity{IdentityHome: t.TempDir()}, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m1"}, time.Millisecond, time.Millisecond, time.Millisecond, "aw")
	if err == nil || !strings.Contains(err.Error(), "system Node executable not found") {
		t.Fatalf("err=%v", err)
	}
	status := runner.Status()
	if !strings.Contains(status.LastError, "system Node executable not found") {
		t.Fatalf("status did not report missing node: %#v", status)
	}
	if !status.LastRunAt.After(time.Time{}) {
		t.Fatalf("last run was not recorded: %#v", status)
	}
}
