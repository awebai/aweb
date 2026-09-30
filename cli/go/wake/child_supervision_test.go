package wake

import (
	"context"
	"encoding/json"
	awid "github.com/awebai/aw/awid"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChildFatalWhileAliveRestarts(t *testing.T) {
	root := t.TempDir()
	writeFakeNode(t, root, "#!/bin/sh\ntrap 'exit 0' TERM\nprintf '{\"type\":\"status\",\"fatal\":true,\"last_error\":\"expired grant\"}\\n'\nwhile IFS= read -r line; do :; done\n")
	store, _ := NewStore(filepath.Join(root, "state"))
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: root}, channelCoreChildConfig{RestartBackoffMin: time.Hour, RestartBackoffMax: time.Hour, ShutdownTimeout: 200 * time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool {
		return st.RestartCount == 1 && strings.Contains(st.LastExit, "expired grant")
	})
}

func TestChildBlockedStdinDoesNotBlockStopOrOffers(t *testing.T) {
	baseline, countOK := openFDCount(t)
	root := t.TempDir()
	writeFakeNode(t, root, "#!/bin/sh\ntrap '' TERM\nprintf '{\"type\":\"status\",\"ready\":true}\\n'\nexec /bin/sleep 30\n")
	store, _ := NewStore(filepath.Join(root, "state"))
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: root}, channelCoreChildConfig{AdmissionSize: 2, ShutdownTimeout: 200 * time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running })
	for i := 0; i < 100; i++ {
		child.offer(childLine{Type: "event", Event: map[string]any{"text": strings.Repeat("x", 128*1024)}})
		child.Pause(i%2 == 0)
	}
	if child.Status().Evicted == 0 {
		t.Fatal("full bounded admission did not count evictions")
	}
	stopped := make(chan struct{})
	go func() { child.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked child stdin wedged Stop")
	}
	assertNoZombieChildren(t)
	if countOK {
		after, _ := openFDCount(t)
		if after > baseline+2 {
			t.Fatalf("child retained descriptors: baseline=%d after=%d", baseline, after)
		}
	}
}

func TestChildGracefulStopDrainsFinalStatus(t *testing.T) {
	root := t.TempDir()
	writeFakeNode(t, root, "#!/bin/sh\ntrap '' TERM\nprintf '{\"type\":\"status\",\"ready\":true}\\n'\nwhile IFS= read -r line; do\n case \"$line\" in *shutdown*) printf '{\"type\":\"status\",\"last_input_at\":\"2026-09-30T18:00:00Z\",\"stopped\":true}\\n'; exit 0;; esac\ndone\n")
	store, _ := NewStore(filepath.Join(root, "state"))
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: root}, channelCoreChildConfig{ShutdownTimeout: 200 * time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running })
	child.Stop()
	if child.Status().LastInputAt.IsZero() {
		t.Fatal("graceful shutdown lost final delivery status")
	}
}

func TestBundledFatalExitsWithStdinStillOpen(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "channel_core_runner_bundle.mjs")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var output strings.Builder
	cmd.Stdout = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	json.NewEncoder(stdin).Encode(initLine{Type: "init", Home: t.TempDir(), Bindings: []childBinding{{BindingID: "bad", IdentityHome: filepath.Join(t.TempDir(), "missing"), TeamID: "invalid"}}})
	err = cmd.Wait()
	if ctx.Err() != nil {
		t.Fatalf("fatal child did not exit while stdin was open: %s", output.String())
	}
	if err == nil || !strings.Contains(output.String(), `"fatal":true`) {
		t.Fatalf("want nonzero fatal exit, got %v: %s", err, output.String())
	}
}

func TestChildStopKillsOwnedGrandchild(t *testing.T) {
	root := t.TempDir()
	pidPath := filepath.Join(root, "grandchild.pid")
	writeFakeNode(t, root, "#!/bin/sh\ntrap '' TERM\n/bin/sleep 30 &\nprintf '%s' \"$!\" > "+shellQuoteForTest(pidPath)+"\nprintf '{\"type\":\"status\",\"ready\":true}\\n'\nwait\n")
	store, _ := NewStore(filepath.Join(root, "state"))
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: root}, channelCoreChildConfig{ShutdownTimeout: 200 * time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running })
	data, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := json.Unmarshal(data, &pid); err != nil {
		t.Fatal(err)
	}
	child.Stop()
	waitForCond(t, "owned grandchild exits", func() bool { return !processAlive(pid) })
}

func TestBundledStopFinishesAcceptedInputAndDeliveryMark(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(filepath.Join(root, "state"))
	inputPath := filepath.Join(root, "input")
	oats := filepath.Join(root, "oats")
	script := "#!/bin/sh\nif [ \"$1 $2\" = \"session inspect\" ]; then printf '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"idle\"}}\\n'; exit 0; fi\ncat > " + shellQuoteForTest(inputPath) + "\n/bin/sleep 0.2\nprintf '{\"ok\":true,\"result\":{\"submitted\":true}}\\n'\n"
	if err := os.WriteFile(oats, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	server := mailServer(t, "finish accepted input")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read"})
	reg := Registration{Home: root, IdentityHome: grantHome, Delivery: DeliverySession}
	child := NewChannelCoreRunner(store).StartChild(context.Background(), reg, channelCoreChildConfig{OatsBin: oats, AWCommand: writeFakeAW(t, root, ""), Coalesce: time.Millisecond, RateLimit: time.Millisecond, InspectDelay: time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running })
	child.Offer(reg.ReceiveBindings()[0], awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-1"})
	waitForFileContains(t, inputPath, "finish accepted input")
	child.Stop()
	data, err := os.ReadFile(filepath.Join(grantHome, "channel-delivered-ids-backend_acme.com.json"))
	if err != nil || !strings.Contains(string(data), "mail-1") {
		t.Fatalf("stop lost accepted input delivery mark: %v %s", err, data)
	}
	if child.Status().LastInputAt.IsZero() {
		t.Fatal("stop lost accepted input status")
	}
	assertNoZombieChildren(t)
}
