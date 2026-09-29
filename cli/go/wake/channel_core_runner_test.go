package wake

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestChannelCoreRunnerReportsMissingSystemNode(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := NewChannelCoreRunner(store)
	t.Setenv("PATH", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	child := runner.StartChild(ctx, Registration{Home: t.TempDir()}, channelCoreChildConfig{AdmissionSize: 1})
	defer child.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := child.Status()
		if strings.Contains(status.LastError, "system Node executable not found") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("status did not report missing node: %#v", child.Status())
}
