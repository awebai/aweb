package wake

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake/session"
)

// clock is a controllable time source. The broker's decisions are all
// time-based, so testing them with sleeps would be both slow and flaky; every
// runner takes its clock from Config.Now.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: at(0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) log(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logCapture) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// harness is one broker with one registered instance, driven synchronously.
//
// The runner is deliberately *not* started: evaluate() is called by hand so a
// test states exactly when a policy step happens. Everything the started
// goroutine would do — absorb a hint, then evaluate — is done here explicitly.
type harness struct {
	t      *testing.T
	broker *Broker
	runner *instanceRunner
	oats   *session.Fake
	store  *Store
	clock  *clock
	logs   *logCapture
	home   string
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	store := tempStore(t)
	home := tempHome(t, "instance")
	clk := newClock()
	logs := &logCapture{}
	oats := session.NewFake(session.Inspection{Home: home, Backend: "herdr", Present: true, State: session.StateIdle, RawState: "idle"})

	cfg := Config{
		Store:         store,
		Session:       oats,
		Coalesce:      2 * time.Second,
		RateLimit:     30 * time.Second,
		PollInterval:  2 * time.Second,
		IdleProbe:     30 * time.Second,
		PendingExpiry: 30 * time.Minute,
		HintCap:       DefaultHintCap,
		Now:           clk.now,
		Log:           logs.log,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	broker, err := NewBroker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reg := Registration{Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession, Backend: "herdr", RegisteredAt: clk.now()}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := broker.instances[HomeKey(home)]
	if runner == nil {
		t.Fatal("registration produced no runner")
	}
	return &harness{t: t, broker: broker, runner: runner, oats: oats, store: store, clock: clk, logs: logs, home: home}
}

func (h *harness) offer(hint Hint) {
	h.t.Helper()
	h.runner.absorb(hintOffer{hint: hint})
}

func (h *harness) mail(id, from string) {
	h.t.Helper()
	hint, ok := HintFromEvent(awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: id, FromAlias: from}, h.clock.now())
	if !ok {
		h.t.Fatal("mail event produced no hint")
	}
	h.offer(hint)
}

func (h *harness) step() {
	h.t.Helper()
	h.runner.evaluate(context.Background())
}

func (h *harness) submissions() []session.Submission { return h.oats.Submissions() }

func newMultiIdentityHarness(t *testing.T, reg Registration, mutate func(*Config)) (*Broker, *instanceRunner, *Store, *clock) {
	t.Helper()
	store := tempStore(t)
	clk := newClock()
	logs := &logCapture{}
	oats := session.NewFake(session.Inspection{Home: reg.Home, Backend: "herdr", Present: true, State: session.StateIdle, RawState: "idle"})
	opened := map[string]int{}
	cfg := Config{
		Store:         store,
		Session:       oats,
		Coalesce:      2 * time.Second,
		RateLimit:     30 * time.Second,
		PollInterval:  2 * time.Second,
		IdleProbe:     30 * time.Second,
		PendingExpiry: 30 * time.Minute,
		HintCap:       DefaultHintCap,
		Now:           clk.now,
		Log:           logs.log,
		OpenStream: func(identityHome string) (run.EventStreamOpener, error) {
			opened[identityHome]++
			return func(context.Context, time.Time) (awid.EventSource, error) { return nil, context.Canceled }, nil
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	broker, err := NewBroker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := broker.instances[HomeKey(reg.Home)]
	if runner == nil {
		t.Fatal("registration produced no runner")
	}
	return broker, runner, store, clk
}

func absorbQueuedHints(t *testing.T, runner *instanceRunner, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		select {
		case offer := <-runner.hints:
			runner.absorb(offer)
		default:
			t.Fatalf("queued hints=%d, want at least %d", i, count)
		}
	}
}

// --- multi-identity receive -------------------------------------------------

func TestMultiIdentityHintsCarryDistinctContextForCollidingMessages(t *testing.T) {
	home := tempHome(t, "instance")
	joinedA := filepath.Join(tempHome(t, "joined-a"), ".aw")
	joinedB := filepath.Join(tempHome(t, "joined-b"), ".aw")
	reg := Registration{
		Home:            home,
		Delivery:        DeliverySession,
		RuntimeDelivery: RuntimeDeliveryExternalSession,
		ReceiveIdentities: []ReceiveIdentity{
			{IdentityHome: joinedA, TeamID: "team:a", Label: "joined-a", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}, Controls: true},
			{IdentityHome: joinedB, TeamID: "team:b", Label: "joined-b", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}},
		},
	}
	broker, runner, _, clk := newMultiIdentityHarness(t, reg, nil)

	ev := awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "same-message-id", FromAlias: "sender"}
	broker.dispatch(joinedA, ev)
	broker.dispatch(joinedB, ev)
	absorbQueuedHints(t, runner, 2)

	runner.mu.Lock()
	pending := append([]Hint(nil), runner.state.Pending...)
	runner.mu.Unlock()
	if len(pending) != 2 {
		t.Fatalf("pending=%#v, want two distinct identity-scoped hints", pending)
	}
	if pending[0].DedupeKey() == pending[1].DedupeKey() {
		t.Fatalf("colliding message ids collapsed across identities: %#v", pending)
	}
	clk.advance(3 * time.Second)
	runner.evaluate(context.Background())
	text := broker.cfg.Session.(*session.Fake).Submissions()[0].Text
	if !strings.Contains(text, "joined-a") || !strings.Contains(text, "joined-b") {
		t.Fatalf("wake text omitted identity contexts:\n%s", text)
	}
	if !strings.Contains(text, "--identity-home") || !strings.Contains(text, "--team 'team:a'") || !strings.Contains(text, "--team 'team:b'") {
		t.Fatalf("wake text omitted exact selectors:\n%s", text)
	}
}

func TestMultiIdentitySecondaryDoesNotControlRuntime(t *testing.T) {
	home := tempHome(t, "instance")
	primary := filepath.Join(tempHome(t, "primary"), ".aw")
	secondary := filepath.Join(tempHome(t, "secondary"), ".aw")
	reg := Registration{
		Home:            home,
		Delivery:        DeliverySession,
		RuntimeDelivery: RuntimeDeliveryExternalSession,
		ReceiveIdentities: []ReceiveIdentity{
			{IdentityHome: primary, Label: "primary", DeliveryOwner: ReceiveOwnerSessionHints, Controls: true},
			{IdentityHome: secondary, Label: "secondary", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail, EventClassChat}},
		},
	}
	broker, runner, _, _ := newMultiIdentityHarness(t, reg, nil)

	broker.dispatch(secondary, awid.AgentEvent{Type: awid.AgentEventControlPause, SignalID: "pause-secondary"})
	runner.mu.Lock()
	paused := runner.state.Paused
	runner.mu.Unlock()
	if paused {
		t.Fatal("secondary identity paused the runtime")
	}

	broker.dispatch(primary, awid.AgentEvent{Type: awid.AgentEventControlPause, SignalID: "pause-primary"})
	runner.mu.Lock()
	paused = runner.state.Paused
	runner.mu.Unlock()
	if !paused {
		t.Fatal("primary controlled identity did not pause the runtime")
	}
}

func TestNativePrimaryStreamIsNotOpenedByBroker(t *testing.T) {
	home := tempHome(t, "instance")
	primary := filepath.Join(tempHome(t, "native-primary"), ".aw")
	joined := filepath.Join(tempHome(t, "joined"), ".aw")
	opened := map[string]int{}
	reg := Registration{
		Home:                home,
		Delivery:            RuntimeDeliveryNativePi,
		RuntimeDelivery:     RuntimeDeliveryNativePi,
		PrimaryIdentityHome: primary,
		ReceiveIdentities: []ReceiveIdentity{{
			IdentityHome:  joined,
			TeamID:        "team:joined",
			Label:         "joined",
			DeliveryOwner: ReceiveOwnerSessionHints,
			EventClasses:  []string{EventClassMail, EventClassChat},
		}},
	}
	broker, runner, _, _ := newMultiIdentityHarness(t, reg, func(cfg *Config) {
		cfg.OpenStream = func(identityHome string) (run.EventStreamOpener, error) {
			opened[identityHome]++
			return func(context.Context, time.Time) (awid.EventSource, error) { return nil, context.Canceled }, nil
		}
	})
	if opened[primary] != 0 {
		t.Fatalf("broker opened native primary stream %d times", opened[primary])
	}
	if opened[joined] != 1 {
		t.Fatalf("joined stream opens=%d, want 1", opened[joined])
	}
	broker.dispatch(primary, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m-primary"})
	runner.mu.Lock()
	pending := len(runner.state.Pending)
	runner.mu.Unlock()
	if pending != 0 {
		t.Fatalf("native primary event reached broker pending hints: %d", pending)
	}
}

func TestMultiIdentityLiveReregistrationWhileRunnerEvaluates(t *testing.T) {
	home := tempHome(t, "instance")
	joinedA := filepath.Join(tempHome(t, "joined-a"), ".aw")
	joinedB := filepath.Join(tempHome(t, "joined-b"), ".aw")
	reg := Registration{
		Home:            home,
		Delivery:        DeliverySession,
		RuntimeDelivery: RuntimeDeliveryExternalSession,
		ReceiveIdentities: []ReceiveIdentity{{
			IdentityHome: joinedA, Label: "joined-a", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}, Controls: true,
		}},
	}
	broker, runner, _, clk := newMultiIdentityHarness(t, reg, nil)
	updated := reg
	updated.ReceiveIdentities = []ReceiveIdentity{{
		IdentityHome: joinedB, Label: "joined-b", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}, Controls: true,
	}}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if i%2 == 0 {
				if err := broker.Register(updated); err != nil {
					t.Errorf("register updated: %v", err)
				}
			} else if err := broker.Register(reg); err != nil {
				t.Errorf("register original: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			clk.advance(time.Second)
			runner.evaluate(context.Background())
		}
	}()
	wg.Wait()
}

func TestMultiIdentityRegistrationUpdateReconcilesReceiveBindings(t *testing.T) {
	home := tempHome(t, "instance")
	joinedA := filepath.Join(tempHome(t, "joined-a"), ".aw")
	joinedB := filepath.Join(tempHome(t, "joined-b"), ".aw")
	reg := Registration{
		Home:            home,
		Delivery:        DeliverySession,
		RuntimeDelivery: RuntimeDeliveryExternalSession,
		ReceiveIdentities: []ReceiveIdentity{{
			IdentityHome: joinedA, Label: "joined-a", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}, Controls: true,
		}},
	}
	broker, runner, store, _ := newMultiIdentityHarness(t, reg, nil)
	if len(broker.Status().Streams) != 1 {
		t.Fatalf("initial streams=%#v", broker.Status().Streams)
	}

	updated := reg
	updated.ReceiveIdentities = []ReceiveIdentity{{
		IdentityHome: joinedB, Label: "joined-b", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}, Controls: true,
	}}
	if err := store.SaveRegistration(updated); err != nil {
		t.Fatal(err)
	}
	broker.Reconcile()
	status := broker.Status()
	if len(status.Streams) != 1 || status.Streams[0].IdentityHome != joinedB {
		t.Fatalf("updated streams=%#v, want only %s", status.Streams, joinedB)
	}
	broker.dispatch(joinedA, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "old"})
	broker.dispatch(joinedB, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "new"})
	absorbQueuedHints(t, runner, 1)
	runner.mu.Lock()
	pending := append([]Hint(nil), runner.state.Pending...)
	runner.mu.Unlock()
	if len(pending) != 1 || pending[0].IdentityHome != joinedB {
		t.Fatalf("pending after update=%#v", pending)
	}
}

func TestMultiIdentityStreamCapAndDeregisterPruneAttachments(t *testing.T) {
	home := tempHome(t, "instance")
	joinedA := filepath.Join(tempHome(t, "joined-a"), ".aw")
	joinedB := filepath.Join(tempHome(t, "joined-b"), ".aw")
	reg := Registration{
		Home:            home,
		Delivery:        DeliverySession,
		RuntimeDelivery: RuntimeDeliveryExternalSession,
		ReceiveIdentities: []ReceiveIdentity{
			{IdentityHome: joinedA, Label: "joined-a", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}, Controls: true},
			{IdentityHome: joinedB, Label: "joined-b", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}},
		},
	}
	broker, _, _, _ := newMultiIdentityHarness(t, reg, func(cfg *Config) { cfg.MaxStreams = 1 })
	status := broker.Status()
	if len(status.Streams) != 2 {
		t.Fatalf("streams=%#v, want live plus over-bound", status.Streams)
	}
	admitted := 0
	for _, stream := range status.Streams {
		if stream.Admitted {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("admitted streams=%d, want 1: %#v", admitted, status.Streams)
	}
	if len(status.Instances) != 1 || len(status.Instances[0].ReceiveIdentities) != 2 {
		t.Fatalf("instance receive status=%#v", status.Instances)
	}
	phases := map[string]string{}
	for _, binding := range status.Instances[0].ReceiveIdentities {
		phases[binding.IdentityHome] = binding.StreamPhase
	}
	if phases[joinedA] == "" || phases[joinedB] == "" {
		t.Fatalf("receive status omitted per-binding stream phases: %#v", status.Instances[0].ReceiveIdentities)
	}
	if existed, err := broker.Deregister(home); err != nil || !existed {
		t.Fatalf("deregister existed=%t err=%v", existed, err)
	}
	if status := broker.Status(); len(status.Streams) != 0 || len(status.Instances) != 0 {
		t.Fatalf("deregister left broker attachments: %#v", status)
	}
}

// --- coalescing and rate limiting -------------------------------------------

func TestBurstCoalescesIntoOneSubmission(t *testing.T) {
	h := newHarness(t, nil)

	h.mail("m1", "alice")
	h.step() // inside the coalescing window: nothing yet
	if n := len(h.submissions()); n != 0 {
		t.Fatalf("submitted %d times inside the coalescing window", n)
	}

	h.clock.advance(500 * time.Millisecond)
	h.mail("m2", "alice")
	h.mail("m3", "bob")
	h.step()
	if n := len(h.submissions()); n != 0 {
		t.Fatalf("submitted %d times inside the coalescing window", n)
	}

	h.clock.advance(2 * time.Second) // the oldest hint is now 2.5s old
	h.step()
	subs := h.submissions()
	if len(subs) != 1 {
		t.Fatalf("a burst produced %d submissions, want 1", len(subs))
	}
	if !strings.Contains(subs[0].Text, "3 items") {
		t.Fatalf("the burst did not collapse into one message:\n%s", subs[0].Text)
	}
	if !strings.Contains(subs[0].Text, "mail from alice (2 unread)") || !strings.Contains(subs[0].Text, "mail from bob (1 unread)") {
		t.Fatalf("summary lost a sender:\n%s", subs[0].Text)
	}

	// The pending set is emptied by the attempt, not marked presented.
	state, _ := h.store.LoadInstance(h.home)
	if len(state.Pending) != 0 {
		t.Fatalf("pending survived a successful submission: %#v", state.Pending)
	}
	if state.LastSubmitAt.IsZero() || state.LastAttemptAt.IsZero() {
		t.Fatal("the attempt was not persisted")
	}
}

func TestReminderIsRateLimitedButNeverSuppressed(t *testing.T) {
	h := newHarness(t, nil)

	h.mail("m1", "alice")
	h.clock.advance(3 * time.Second)
	h.step()
	if len(h.submissions()) != 1 {
		t.Fatalf("first submission did not happen: %d", len(h.submissions()))
	}

	// The reconnect snapshot re-raises the same still-unread item. It is not
	// suppressed — there is no presented mark — but it is rate limited.
	h.clock.advance(3 * time.Second)
	h.mail("m1", "alice")
	h.clock.advance(3 * time.Second)
	h.step()
	if n := len(h.submissions()); n != 1 {
		t.Fatalf("the rate limit did not hold: %d submissions", n)
	}
	state, _ := h.store.LoadInstance(h.home)
	if len(state.Pending) != 1 {
		t.Fatalf("the re-raised item was dropped rather than held: %#v", state.Pending)
	}

	h.clock.advance(30 * time.Second)
	h.step()
	if n := len(h.submissions()); n != 2 {
		t.Fatalf("the reminder never arrived: %d submissions", n)
	}
}

// TestFailedSubmissionIsRateLimitedToo: the note persists "last attempt", not
// "last success", so a refusing target is retried on the same floor rather than
// every poll.
func TestFailedSubmissionIsRateLimitedAndKeepsHints(t *testing.T) {
	h := newHarness(t, nil)
	h.oats.InputErr = &session.Error{Code: "E_TARGET_REPLACED", Message: "tmux window identity changed"}

	h.mail("m1", "alice")
	h.clock.advance(3 * time.Second)
	h.step()
	if len(h.submissions()) != 1 {
		t.Fatalf("attempts=%d", len(h.submissions()))
	}
	state, _ := h.store.LoadInstance(h.home)
	if len(state.Pending) != 1 {
		t.Fatalf("a refused input dropped the hint: %#v", state.Pending)
	}
	if !state.LastSubmitAt.IsZero() {
		t.Fatal("a refusal was recorded as a submission")
	}

	h.clock.advance(2 * time.Second)
	h.step()
	if n := len(h.submissions()); n != 1 {
		t.Fatalf("a refusing target was retried %d times inside the rate limit", n)
	}
	h.clock.advance(40 * time.Second)
	h.step()
	if n := len(h.submissions()); n != 2 {
		t.Fatalf("the retry never happened: %d", n)
	}
}

// --- state policy in the running broker -------------------------------------

func TestWorkingAndBlockedProduceNoInputCall(t *testing.T) {
	for _, raw := range []string{"working", "blocked", "shell", "generic shell"} {
		t.Run(raw, func(t *testing.T) {
			h := newHarness(t, nil)
			h.oats.Script(session.Scripted{Inspection: session.Inspection{
				Home: h.home, Backend: "herdr", Present: true,
				State: session.NormalizeState(raw), RawState: raw,
			}})
			h.mail("m1", "alice")
			for i := 0; i < 5; i++ {
				h.clock.advance(3 * time.Second)
				h.step()
			}
			if n := len(h.submissions()); n != 0 {
				t.Fatalf("typed into a %q instance %d times", raw, n)
			}
			state, _ := h.store.LoadInstance(h.home)
			if len(state.Pending) != 1 {
				t.Fatalf("a deferred hint was lost: %#v", state.Pending)
			}
		})
	}
}

func TestUnknownSubmitsWithNoInitialDelay(t *testing.T) {
	// tmux always says unknown and promises no readiness. The policy is
	// coalescing plus a rate limit, not a delay (§4).
	h := newHarness(t, nil)
	h.oats.Script(session.Scripted{Inspection: session.Inspection{
		Home: h.home, Backend: "tmux", Present: true, State: session.StateUnknown, RawState: "unknown",
	}})
	h.mail("m1", "alice")
	h.clock.advance(2 * time.Second)
	h.step()
	if n := len(h.submissions()); n != 1 {
		t.Fatalf("unknown produced %d submissions; the only bounds are the window and the rate limit", n)
	}
}

func TestStoppedMarksInactiveOnlyAfterAConfirmedLiveObservation(t *testing.T) {
	h := newHarness(t, nil)

	// Before any confirmed live inspect, a stopped report concludes nothing.
	h.oats.Script(session.Scripted{Inspection: session.Inspection{
		Home: h.home, Present: false, State: session.StateStopped, RawState: "stopped",
	}})
	h.mail("m1", "alice")
	h.clock.advance(3 * time.Second)
	h.step()
	state, _ := h.store.LoadInstance(h.home)
	if state.Inactive {
		t.Fatal("a pending home was marked inactive from a stopped report it never earned")
	}

	// One live observation, then stopped: now it means inactive, and the
	// registration is kept for the retire hook.
	h.oats.Script(
		session.Scripted{Inspection: session.Inspection{Home: h.home, Backend: "herdr", Present: true, State: session.StateBusy, RawState: "working"}},
		session.Scripted{Inspection: session.Inspection{Home: h.home, Backend: "herdr", Present: false, State: session.StateStopped, RawState: "stopped"}},
	)
	h.clock.advance(3 * time.Second)
	h.step()
	h.clock.advance(3 * time.Second)
	h.step()

	state, _ = h.store.LoadInstance(h.home)
	if !state.Inactive {
		t.Fatal("stopped after a confirmed live observation did not mark the registration inactive")
	}
	if _, ok, _ := h.store.LoadRegistration(h.home); !ok {
		t.Fatal("the broker removed a registration; removal belongs to the retire hook")
	}
	if !strings.Contains(h.logs.all(), "inactive home=") {
		t.Fatalf("no log line at the inactive transition:\n%s", h.logs.all())
	}
	if !strings.Contains(h.logs.all(), "present home=") {
		t.Fatalf("no log line at the present transition:\n%s", h.logs.all())
	}
}

// --- pending tolerance and expiry -------------------------------------------

func TestPendingHomeToleratesEveryErrorAndSubmitsNothing(t *testing.T) {
	h := newHarness(t, nil)
	h.oats.Script(
		session.Scripted{Err: &session.Error{Code: session.CodeRuntimeEndpointUnknown, Message: "cannot read session receipt"}},
		session.Scripted{Err: &session.Error{Code: "E_OATS_UNREACHABLE", Message: "exec: oats: not found"}},
		session.Scripted{Err: &session.Error{Code: "E_SOMETHING_NEW", Message: "a code this broker has never seen"}},
		session.Scripted{Inspection: session.Inspection{Home: h.home, Present: false, State: session.StateUnknown, RawState: "unknown"}},
	)

	h.mail("m1", "alice")
	for i := 0; i < 4; i++ {
		h.clock.advance(3 * time.Second)
		h.step()
	}
	if n := len(h.submissions()); n != 0 {
		t.Fatalf("submitted %d times before the first confirmed live inspect", n)
	}
	state, _ := h.store.LoadInstance(h.home)
	if state.Inactive {
		t.Fatal("a tolerated error was read as a verdict")
	}
	if len(state.Pending) != 1 {
		t.Fatalf("hints for a pending home must be kept and delivered once it is present: %#v", state.Pending)
	}
	if _, ok, _ := h.store.LoadRegistration(h.home); !ok {
		t.Fatal("a pending registration was dropped before its expiry")
	}

	// The instance comes up: the kept hint is delivered.
	h.oats.Script(session.Scripted{Inspection: session.Inspection{Home: h.home, Backend: "tmux", Present: true, State: session.StateUnknown, RawState: "unknown"}})
	h.clock.advance(3 * time.Second)
	h.step()
	if n := len(h.submissions()); n != 1 {
		t.Fatalf("the kept hint was not delivered on first presence: %d", n)
	}
}

func TestPendingRegistrationExpiresAtThirtyMinutes(t *testing.T) {
	if DefaultPendingExpiry != 30*time.Minute {
		t.Fatalf("DefaultPendingExpiry=%s; the note fixes 30 minutes", DefaultPendingExpiry)
	}
	h := newHarness(t, nil)
	h.oats.Script(session.Scripted{Err: &session.Error{Code: session.CodeRuntimeEndpointUnknown, Message: "cannot read session receipt"}})

	h.mail("m1", "alice")
	h.clock.advance(29 * time.Minute)
	h.step()
	if _, ok, _ := h.store.LoadRegistration(h.home); !ok {
		t.Fatal("the registration was dropped early")
	}

	h.clock.advance(2 * time.Minute)
	h.step()
	if _, ok, _ := h.store.LoadRegistration(h.home); ok {
		t.Fatal("a registration still pending at 30 minutes was not dropped")
	}
	logs := h.logs.all()
	if !strings.Contains(logs, "expired home=") || !strings.Contains(logs, "pending_for=31m0s") {
		t.Fatalf("expiry did not write one log line naming the home and the elapsed time:\n%s", logs)
	}
	if n := len(h.submissions()); n != 0 {
		t.Fatalf("submitted %d times while pending", n)
	}
}

// TestConfirmedInstanceIsNeverExpired: expiry is a bound on registrations that
// never came up, not a lease on live ones.
func TestConfirmedInstanceIsNeverExpired(t *testing.T) {
	h := newHarness(t, nil)
	h.clock.advance(3 * time.Second)
	h.step() // confirms presence
	h.clock.advance(10 * time.Hour)
	h.step()
	if _, ok, _ := h.store.LoadRegistration(h.home); !ok {
		t.Fatal("a live instance was expired")
	}
}

// --- pause and resume -------------------------------------------------------

func TestPauseSuppressesTypingAndSurvivesARestart(t *testing.T) {
	h := newHarness(t, nil)

	if err := h.broker.SetPaused(h.home, true); err != nil {
		t.Fatal(err)
	}
	h.mail("m1", "alice")
	h.clock.advance(3 * time.Second)
	h.step()
	if n := len(h.submissions()); n != 0 {
		t.Fatalf("a paused instance was typed into %d times", n)
	}
	state, _ := h.store.LoadInstance(h.home)
	if !state.Paused {
		t.Fatal("pause is not durable")
	}
	if len(state.Pending) != 1 {
		t.Fatal("pause dropped a hint; it suppresses typing, not delivery")
	}

	// Restart: a new broker over the same state directory.
	restarted := h.restart(t)
	restartedState, _ := restarted.store.LoadInstance(restarted.home)
	if !restartedState.Paused {
		t.Fatal("pause did not survive the restart")
	}
	restarted.clock.advance(3 * time.Second)
	restarted.step()
	if n := len(restarted.submissions()); n != 0 {
		t.Fatalf("a paused instance was typed into after a restart (%d times)", n)
	}

	if err := restarted.broker.SetPaused(restarted.home, false); err != nil {
		t.Fatal(err)
	}
	restarted.clock.advance(3 * time.Second)
	restarted.step()
	if n := len(restarted.submissions()); n != 1 {
		t.Fatalf("resume did not restore typing: %d submissions", n)
	}
	logs := restarted.logs.all() + h.logs.all()
	if !strings.Contains(logs, "paused home=") || !strings.Contains(logs, "resumed home=") {
		t.Fatalf("pause and resume did not write log lines:\n%s", logs)
	}
}

func TestControlPauseAndResumeEventsSetDurableState(t *testing.T) {
	h := newHarness(t, nil)
	identityHome := h.runner.reg.IdentityHome

	h.broker.dispatch(identityHome, awid.AgentEvent{Type: awid.AgentEventControlPause})
	state, _ := h.store.LoadInstance(h.home)
	if !state.Paused {
		t.Fatal("control_pause did not set durable pause state")
	}
	h.broker.dispatch(identityHome, awid.AgentEvent{Type: awid.AgentEventControlResume})
	state, _ = h.store.LoadInstance(h.home)
	if state.Paused {
		t.Fatal("control_resume did not clear durable pause state")
	}

	// A control_interrupt is transient: it produces a hint, and the hint is not
	// written to disk, so one lost across a stream gap is not replayed.
	h.broker.dispatch(identityHome, awid.AgentEvent{Type: awid.AgentEventControlInterrupt, SignalID: "sig-1"})
	h.runner.absorb(<-h.runner.hints)
	state, _ = h.store.LoadInstance(h.home)
	if len(state.Pending) != 0 {
		t.Fatalf("a transient control signal was persisted: %#v", state.Pending)
	}
	if len(h.runner.state.Pending) != 1 {
		t.Fatalf("the transient hint was not queued in memory: %#v", h.runner.state.Pending)
	}
}

// --- restart ----------------------------------------------------------------

// restart builds a second broker over the same state directory, the way a
// daemon restart does. Nothing is handed over in memory.
func (h *harness) restart(t *testing.T) *harness {
	t.Helper()
	logs := &logCapture{}
	oats := session.NewFake(session.Inspection{Home: h.home, Backend: "herdr", Present: true, State: session.StateIdle, RawState: "idle"})
	broker, err := NewBroker(Config{
		Store:         h.store,
		Session:       oats,
		Coalesce:      2 * time.Second,
		RateLimit:     30 * time.Second,
		PollInterval:  2 * time.Second,
		IdleProbe:     30 * time.Second,
		PendingExpiry: 30 * time.Minute,
		Now:           h.clock.now,
		Log:           logs.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker.Reconcile()
	runner := broker.instances[HomeKey(h.home)]
	if runner == nil {
		t.Fatal("the restarted daemon did not re-read the registration from disk")
	}
	return &harness{t: t, broker: broker, runner: runner, oats: oats, store: h.store, clock: h.clock, logs: logs, home: h.home}
}

func TestRestartRereadsRegistrationsAndPendingHints(t *testing.T) {
	h := newHarness(t, nil)

	// A working instance holds its hints; then the daemon dies.
	h.oats.Script(session.Scripted{Inspection: session.Inspection{Home: h.home, Backend: "herdr", Present: true, State: session.StateBusy, RawState: "working"}})
	h.mail("m1", "alice")
	h.mail("m2", "alice")
	h.clock.advance(3 * time.Second)
	h.step()
	if len(h.submissions()) != 0 {
		t.Fatal("typed into a working instance")
	}

	restarted := h.restart(t)
	state, _ := restarted.store.LoadInstance(restarted.home)
	if len(state.Pending) != 2 {
		t.Fatalf("pending hints did not survive the restart: %#v", state.Pending)
	}
	if !state.ConfirmedLive() {
		t.Fatal("the confirmed-live observation did not survive the restart")
	}

	restarted.clock.advance(60 * time.Second)
	restarted.step()
	subs := restarted.submissions()
	if len(subs) != 1 {
		t.Fatalf("the restarted daemon submitted %d times, want 1", len(subs))
	}
	if !strings.Contains(subs[0].Text, "2 items") {
		t.Fatalf("hints held across the restart were lost:\n%s", subs[0].Text)
	}
}

// TestNothingOnDiskIsAPresentedMark reads the whole state directory back and
// asserts it holds no field that could suppress a future wake.
func TestNothingOnDiskIsAPresentedMark(t *testing.T) {
	h := newHarness(t, nil)
	h.mail("m1", "alice")
	h.clock.advance(3 * time.Second)
	h.step()
	if len(h.submissions()) != 1 {
		t.Fatal("setup did not submit")
	}

	// The submitted item can be raised again immediately, and is: nothing
	// durable remembers that it was typed.
	h.mail("m1", "alice")
	h.clock.advance(60 * time.Second)
	h.step()
	if n := len(h.submissions()); n != 2 {
		t.Fatalf("a re-raised item was suppressed by something durable (%d submissions)", n)
	}

	state, _ := h.store.LoadInstance(h.home)
	if state.Pending != nil && len(state.Pending) != 0 {
		t.Fatalf("pending=%#v", state.Pending)
	}
	// The persisted vocabulary is attempts, never delivery marks. Home is
	// cleared first: it is a temp path carrying this test's own name, and the
	// name contains one of the words being searched for.
	state.Home = ""
	encoded := strings.ToLower(jsonOf(t, state))
	for _, forbidden := range []string{"presented", "delivered", "acked", "read_at"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("instance state holds a %q field:\n%s", forbidden, encoded)
		}
	}
}

// --- stream bound -----------------------------------------------------------

func TestStreamBoundReportsRatherThanDrops(t *testing.T) {
	store := tempStore(t)
	clk := newClock()
	logs := &logCapture{}

	var mu sync.Mutex
	opened := []string{}
	broker, err := NewBroker(Config{
		Store:      store,
		Session:    session.NewFake(session.Inspection{Present: true, State: session.StateIdle, RawState: "idle"}),
		MaxStreams: 1,
		Now:        clk.now,
		Log:        logs.log,
		OpenStream: func(identityHome string) (run.EventStreamOpener, error) {
			mu.Lock()
			opened = append(opened, identityHome)
			mu.Unlock()
			return func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	first := tempHome(t, "first")
	second := tempHome(t, "second")
	for _, home := range []string{first, second} {
		if err := broker.Register(Registration{
			Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession, RegisteredAt: clk.now(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	mu.Lock()
	count := len(opened)
	mu.Unlock()
	if count != 1 {
		t.Fatalf("opened %d streams under a bound of 1", count)
	}

	status := broker.Status()
	if len(status.Instances) != 2 {
		t.Fatalf("a registration over the bound was dropped: %#v", status.Instances)
	}
	overBound := 0
	for _, stream := range status.Streams {
		if !stream.Admitted {
			overBound++
		}
	}
	if overBound != 1 {
		t.Fatalf("the over-bound identity is not reported in status: %#v", status.Streams)
	}
	if !strings.Contains(logs.all(), "stream bound reached") {
		t.Fatalf("no log line at the stream bound:\n%s", logs.all())
	}

	// Freeing the slot admits the waiting registration on the next reconcile.
	if _, err := broker.Deregister(first); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	count = len(opened)
	mu.Unlock()
	if count != 2 {
		t.Fatalf("a freed slot did not admit the waiting registration (opened=%d)", count)
	}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
