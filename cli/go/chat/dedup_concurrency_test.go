package chat

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The delivery store is the replay barrier: a message whose mark is missing is
// filtered as undelivered and dispatched again. Losing marks therefore causes
// duplicate model invocations and repeated human-visible messages.
//
// SaveDeliveredIDsForDir was an unlocked read-merge-write over one whole file,
// so concurrent writers each merged onto a snapshot taken before the others
// wrote and the last rename won. The loss was silent: every writer returned nil,
// so a caller could not detect it even in principle (default-aajc.10).
//
// Concurrency here is a normal operating condition, not a corner case: the
// `aw run` wake loop and any `aw chat` invocation in the same worktree write
// this same file.

const barrierEnv = "AW_TEST_DEDUP_BARRIER"

// TestMain lets the test binary re-exec itself as a real, separate process so
// the barrier tests exercise cross-process contention rather than goroutines.
func TestMain(m *testing.M) {
	if spec := os.Getenv(barrierEnv); spec != "" {
		os.Exit(runBarrierChild(spec))
	}
	os.Exit(m.Run())
}

// runBarrierChild waits for the release file, then records its ids. Spec is
// "<dir>|<releaseFile>|<id>,<id>...".
func runBarrierChild(spec string) int {
	parts := strings.SplitN(spec, "|", 3)
	if len(parts) != 3 {
		fmt.Fprintln(os.Stderr, "bad barrier spec")
		return 2
	}
	dir, release, ids := parts[0], parts[1], strings.Split(parts[2], ",")

	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(release); err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "barrier never released")
			return 3
		}
		time.Sleep(time.Millisecond)
	}
	if err := SaveDeliveredIDsForDir(dir, ids); err != nil {
		fmt.Fprintf(os.Stderr, "save failed: %v\n", err)
		return 1
	}
	return 0
}

func assertNoMarksLost(t *testing.T, dir string, want []string) {
	t.Helper()
	delivered, err := LoadDeliveredIDsForDir(dir)
	if err != nil {
		t.Fatalf("load delivered ids: %v", err)
	}
	var lost []string
	for _, id := range want {
		if _, ok := delivered[id]; !ok {
			lost = append(lost, id)
		}
	}
	if len(lost) > 0 {
		t.Errorf("%d of %d delivery marks lost despite every writer reporting success: %v",
			len(lost), len(want), lost)
	}
}

// Concurrent writers inside one process. Each does its own read-merge-write, so
// this races exactly the way separate processes do.
func TestConcurrentWritersKeepEveryDeliveryMark(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(DeliveredIDsPathEnv, filepath.Join(dir, "chat-delivered-ids.json"))

	const writers = 16
	want := make([]string, writers)
	for i := range want {
		want[i] = fmt.Sprintf("msg-%02d", i)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = SaveDeliveredIDsForDir(dir, []string{want[i]})
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	assertNoMarksLost(t, dir, want)
}

// The same contention across REAL processes, released together by a barrier.
// This is the shape that actually occurs: an `aw run` loop and an `aw chat`
// command writing the same worktree file at once.
func TestConcurrentProcessesKeepEveryDeliveryMark(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns subprocesses")
	}
	dir := t.TempDir()
	storePath := filepath.Join(dir, "chat-delivered-ids.json")
	release := filepath.Join(dir, "release")
	// The parent reads through the same override the children write through;
	// without this they would resolve different files and the test would report
	// a total loss that is a fixture bug, not a defect.
	t.Setenv(DeliveredIDsPathEnv, storePath)

	const procs = 12
	want := make([]string, procs)
	cmds := make([]*exec.Cmd, procs)
	var stderrs []*strings.Builder

	for i := 0; i < procs; i++ {
		want[i] = fmt.Sprintf("proc-%02d", i)
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("%s=%s|%s|%s", barrierEnv, dir, release, want[i]),
			DeliveredIDsPathEnv+"="+storePath,
		)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		stderrs = append(stderrs, &stderr)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start child %d: %v", i, err)
		}
		cmds[i] = cmd
	}

	// Everyone is spawned and spinning; release them together.
	if err := os.WriteFile(release, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child %d failed: %v\n%s", i, err, stderrs[i].String())
		}
	}

	assertNoMarksLost(t, dir, want)
}

// Repeated ids across processes must not corrupt the store or drop the distinct
// ones, and re-marking an id already present is idempotent.
func TestConcurrentProcessesWithOverlappingIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns subprocesses")
	}
	dir := t.TempDir()
	storePath := filepath.Join(dir, "chat-delivered-ids.json")
	release := filepath.Join(dir, "release")
	t.Setenv(DeliveredIDsPathEnv, storePath)

	const procs = 10
	shared := "shared-msg"
	want := []string{shared}
	var cmds []*exec.Cmd
	var stderrs []*strings.Builder

	for i := 0; i < procs; i++ {
		own := fmt.Sprintf("own-%02d", i)
		want = append(want, own)
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("%s=%s|%s|%s,%s", barrierEnv, dir, release, shared, own),
			DeliveredIDsPathEnv+"="+storePath,
		)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		stderrs = append(stderrs, &stderr)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start child %d: %v", i, err)
		}
		cmds = append(cmds, cmd)
	}
	if err := os.WriteFile(release, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child %d failed: %v\n%s", i, err, stderrs[i].String())
		}
	}
	assertNoMarksLost(t, dir, want)
}

// A mark that survived must keep filtering after a restart: the barrier is only
// useful if it is durable.
func TestDeliveryMarksSurviveReload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(DeliveredIDsPathEnv, filepath.Join(dir, "chat-delivered-ids.json"))

	if err := SaveDeliveredIDsForDir(dir, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveDeliveredIDsForDir(dir, []string{"c"}); err != nil {
		t.Fatal(err)
	}
	assertNoMarksLost(t, dir, []string{"a", "b", "c"})
}
