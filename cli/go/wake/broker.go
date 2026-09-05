package wake

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake/session"
)

// Defaults from docs/terminal-wake-broker.md §4, and the two bounds the note
// leaves to the implementation.
const (
	// DefaultMaxStreams is the accepted configurable initial bound, not a
	// measured one. Registrations beyond it are reported in status, never
	// silently dropped (§4).
	DefaultMaxStreams = 128

	// DefaultCoalesce is the short window over which a burst of hints for one
	// instance collapses into one submission.
	DefaultCoalesce = 2 * time.Second

	// DefaultRateLimit is the floor between two submission attempts for one
	// instance. The note fixes no number; it requires that reminders be
	// rate-limited per instance, and that `unknown` be bounded by coalescing
	// plus a rate limit rather than by a delay.
	DefaultRateLimit = 30 * time.Second

	// DefaultPollInterval is the inspect poll. Deferred hints are re-evaluated
	// on each poll with an unbounded wait (§4).
	DefaultPollInterval = 2 * time.Second

	// DefaultIdleProbe is how often an instance with nothing pending is still
	// inspected, so `stopped` is noticed without polling every instance every
	// two seconds.
	DefaultIdleProbe = 30 * time.Second

	// DefaultPendingExpiry drops a registration that never reached a confirmed
	// live inspect. The bound is operational visibility, not data safety: it
	// deletes no server messages, and a home that comes up later is re-raised
	// by the reconnect snapshot (§4).
	DefaultPendingExpiry = 30 * time.Minute

	// DefaultReconcile is how often the daemon re-reads registry.d, so a
	// registration written by the socket fallback while the daemon was busy is
	// picked up without a restart.
	DefaultReconcile = 10 * time.Second
)

// Config configures a Broker.
type Config struct {
	Store   *Store
	Session session.Client

	// OpenStream builds the event stream source for one identity home. It is
	// injected so the broker can be tested with no server and no credentials,
	// and so credential resolution stays in cmd/aw where it already lives.
	OpenStream func(identityHome string) (run.EventStreamOpener, error)

	MaxStreams    int
	Coalesce      time.Duration
	RateLimit     time.Duration
	PollInterval  time.Duration
	IdleProbe     time.Duration
	PendingExpiry time.Duration
	Reconcile     time.Duration
	HintCap       int
	StreamTTL     time.Duration
	BackoffMin    time.Duration
	BackoffMax    time.Duration

	Now func() time.Time
	Log func(string, ...any)
}

func (c *Config) applyDefaults() {
	if c.MaxStreams <= 0 {
		c.MaxStreams = DefaultMaxStreams
	}
	if c.Coalesce <= 0 {
		c.Coalesce = DefaultCoalesce
	}
	if c.RateLimit <= 0 {
		c.RateLimit = DefaultRateLimit
	}
	if c.PollInterval <= 0 {
		c.PollInterval = DefaultPollInterval
	}
	if c.IdleProbe <= 0 {
		c.IdleProbe = DefaultIdleProbe
	}
	if c.PendingExpiry <= 0 {
		c.PendingExpiry = DefaultPendingExpiry
	}
	if c.Reconcile <= 0 {
		c.Reconcile = DefaultReconcile
	}
	if c.HintCap <= 0 {
		c.HintCap = DefaultHintCap
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	if c.Log == nil {
		c.Log = func(string, ...any) {}
	}
}

// Broker is the host daemon: one reconnecting stream per registered identity
// home, one runner per registered instance home.
type Broker struct {
	cfg Config

	// reconcileMu serialises the whole reconcile step. Register, Deregister,
	// the reconcile ticker and the expiry path can all reach it at once, and
	// the step is a check-then-act on two maps: without this, two concurrent
	// reconciles could each see one home as "not running" and start two
	// runners for it, or each pass the stream bound and open one stream too
	// many. It is held across the per-runner start/stop calls, which never
	// take it themselves.
	reconcileMu sync.Mutex

	mu        sync.Mutex
	streams   map[string]*streamRunner
	instances map[string]*instanceRunner
	// overBound holds identity homes refused a stream by MaxStreams.
	overBound map[string]struct{}

	ctx context.Context
}

// NewBroker builds a Broker. Store and Session are required.
func NewBroker(cfg Config) (*Broker, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("wake: store is required")
	}
	if cfg.Session == nil {
		return nil, fmt.Errorf("wake: session client is required")
	}
	cfg.applyDefaults()
	return &Broker{
		cfg:       cfg,
		streams:   map[string]*streamRunner{},
		instances: map[string]*instanceRunner{},
		overBound: map[string]struct{}{},
	}, nil
}

// Run reconciles the registration files and serves until ctx is cancelled.
// It is safe to start at any time: all state is on disk and there is no cursor.
func (b *Broker) Run(ctx context.Context) error {
	b.ctx = ctx
	b.Reconcile()
	b.writeStatus()

	reconcile := time.NewTicker(b.cfg.Reconcile)
	defer reconcile.Stop()
	status := time.NewTicker(b.cfg.PollInterval)
	defer status.Stop()

	for {
		select {
		case <-ctx.Done():
			b.shutdown()
			return nil
		case <-reconcile.C:
			b.Reconcile()
		case <-status.C:
			b.writeStatus()
		}
	}
}

func (b *Broker) shutdown() {
	b.mu.Lock()
	streams := make([]*streamRunner, 0, len(b.streams))
	for _, s := range b.streams {
		streams = append(streams, s)
	}
	instances := make([]*instanceRunner, 0, len(b.instances))
	for _, r := range b.instances {
		instances = append(instances, r)
	}
	b.streams = map[string]*streamRunner{}
	b.instances = map[string]*instanceRunner{}
	b.mu.Unlock()

	for _, r := range instances {
		r.stop()
	}
	for _, s := range streams {
		s.stop()
	}
	b.writeStatus()
}

// Reconcile brings the running set in line with registry.d. It is called on
// start, on a timer, and immediately after a socket register or deregister.
func (b *Broker) Reconcile() {
	b.reconcileMu.Lock()
	defer b.reconcileMu.Unlock()
	b.reconcileLocked()
}

func (b *Broker) reconcileLocked() {
	registrations, err := b.cfg.Store.ListRegistrations()
	if err != nil {
		b.cfg.Log("reconcile failed err=%v", err)
		return
	}

	seen := map[string]struct{}{}
	for _, reg := range registrations {
		canonical, err := CanonicalHome(reg.Home)
		if err != nil {
			b.cfg.Log("registration refused home=%q err=%v", reg.Home, err)
			continue
		}
		reg.Home = canonical
		if err := reg.Validate(); err != nil {
			// A file written by the socket fallback gets the same exclusivity
			// check the command applies; the daemon never trusts the file
			// because a command wrote it.
			b.cfg.Log("registration refused home=%s err=%v", canonical, err)
			continue
		}
		key := HomeKey(canonical)
		seen[key] = struct{}{}

		b.mu.Lock()
		_, running := b.instances[key]
		b.mu.Unlock()
		if running {
			continue
		}
		b.startInstance(reg)
	}

	b.mu.Lock()
	stale := []*instanceRunner{}
	for key, runner := range b.instances {
		if _, ok := seen[key]; !ok {
			stale = append(stale, runner)
			delete(b.instances, key)
		}
	}
	b.mu.Unlock()
	for _, runner := range stale {
		b.cfg.Log("deregistered home=%s", runner.reg.Home)
		runner.stop()
	}
	b.pruneStreamsLocked()
}

func (b *Broker) startInstance(reg Registration) {
	state, err := b.cfg.Store.LoadInstance(reg.Home)
	if err != nil {
		b.cfg.Log("state unreadable home=%s err=%v", reg.Home, err)
		state = InstanceState{Home: reg.Home}
	}
	state.Home = reg.Home

	runner := newInstanceRunner(b, reg, state)
	b.mu.Lock()
	b.instances[HomeKey(reg.Home)] = runner
	b.mu.Unlock()

	admitted := b.ensureStream(reg.IdentityHome)
	runner.setStreamAdmitted(admitted)
	b.cfg.Log("registered home=%s identity_home=%s backend=%s delivery=%s pending_hints=%d stream=%s",
		reg.Home, reg.IdentityHome, orDash(reg.Backend), reg.Delivery, len(state.Pending), admittedLabel(admitted))
	if b.ctx != nil {
		runner.start(b.ctx)
	}
}

func admittedLabel(admitted bool) string {
	if admitted {
		return "admitted"
	}
	return "over-bound"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// ensureStream opens the identity's stream if it is not already open and the
// stream bound allows it. It reports whether the identity has a stream.
func (b *Broker) ensureStream(identityHome string) bool {
	identityHome = strings.TrimSpace(identityHome)
	if identityHome == "" {
		return false
	}
	b.mu.Lock()
	if _, ok := b.streams[identityHome]; ok {
		b.mu.Unlock()
		return true
	}
	if len(b.streams) >= b.cfg.MaxStreams {
		b.overBound[identityHome] = struct{}{}
		b.mu.Unlock()
		b.cfg.Log("stream bound reached identity_home=%s max_streams=%d (registration kept and reported in status)", identityHome, b.cfg.MaxStreams)
		return false
	}
	b.mu.Unlock()

	if b.cfg.OpenStream == nil {
		return false
	}
	opener, err := b.cfg.OpenStream(identityHome)
	if err != nil {
		b.cfg.Log("stream unavailable identity_home=%s err=%v", identityHome, err)
		return false
	}
	runner := newStreamRunner(identityHome, opener, func(ev awid.AgentEvent) {
		b.dispatch(identityHome, ev)
	}, b.cfg.Log, b.cfg.Now, b.cfg.StreamTTL, b.cfg.BackoffMin, b.cfg.BackoffMax)

	b.mu.Lock()
	if _, ok := b.streams[identityHome]; ok {
		b.mu.Unlock()
		return true
	}
	b.streams[identityHome] = runner
	delete(b.overBound, identityHome)
	b.mu.Unlock()
	if b.ctx != nil {
		runner.start(b.ctx)
	}
	return true
}

// pruneStreams stops streams no registration needs any more.
func (b *Broker) pruneStreams() {
	b.reconcileMu.Lock()
	defer b.reconcileMu.Unlock()
	b.pruneStreamsLocked()
}

func (b *Broker) pruneStreamsLocked() {
	needed := map[string]struct{}{}
	b.mu.Lock()
	for _, runner := range b.instances {
		needed[runner.reg.IdentityHome] = struct{}{}
	}
	orphans := []*streamRunner{}
	for identityHome, runner := range b.streams {
		if _, ok := needed[identityHome]; !ok {
			orphans = append(orphans, runner)
			delete(b.streams, identityHome)
		}
	}
	for identityHome := range b.overBound {
		if _, ok := needed[identityHome]; !ok {
			delete(b.overBound, identityHome)
		}
	}
	b.mu.Unlock()
	for _, runner := range orphans {
		runner.stop()
	}
	// A freed slot may now admit a registration that was over the bound.
	b.mu.Lock()
	pending := make([]*instanceRunner, 0)
	for _, runner := range b.instances {
		if !runner.streamAdmitted() {
			pending = append(pending, runner)
		}
	}
	b.mu.Unlock()
	for _, runner := range pending {
		runner.setStreamAdmitted(b.ensureStream(runner.reg.IdentityHome))
	}
}

// dispatch fans one identity's event out to every instance registered under
// that identity home.
func (b *Broker) dispatch(identityHome string, ev awid.AgentEvent) {
	b.mu.Lock()
	targets := make([]*instanceRunner, 0, len(b.instances))
	for _, runner := range b.instances {
		if runner.reg.IdentityHome == identityHome {
			targets = append(targets, runner)
		}
	}
	b.mu.Unlock()

	now := b.cfg.Now()
	switch ev.Type {
	case awid.AgentEventControlPause:
		for _, runner := range targets {
			runner.setPaused(true, "control_pause")
		}
		return
	case awid.AgentEventControlResume:
		for _, runner := range targets {
			runner.setPaused(false, "control_resume")
		}
		return
	}

	hint, ok := HintFromEvent(ev, now)
	if !ok {
		return
	}
	for _, runner := range targets {
		runner.offer(hint, ev.UnreadCount)
	}
}

// Register validates and stores a registration, then reconciles.
func (b *Broker) Register(reg Registration) error {
	canonical, err := CanonicalHome(reg.Home)
	if err != nil {
		return err
	}
	reg.Home = canonical
	if err := reg.Validate(); err != nil {
		return err
	}
	if reg.RegisteredAt.IsZero() {
		reg.RegisteredAt = b.cfg.Now()
	}
	if existing, ok, _ := b.cfg.Store.LoadRegistration(canonical); ok {
		// Re-registration keeps the original clock so the pending expiry is
		// not restarted by a retrying hook.
		reg.RegisteredAt = existing.RegisteredAt
	}
	if err := b.cfg.Store.SaveRegistration(reg); err != nil {
		return err
	}
	b.Reconcile()
	return nil
}

// Deregister removes a registration and its state.
func (b *Broker) Deregister(home string) (bool, error) {
	existed, err := b.cfg.Store.DeleteRegistration(home)
	if err != nil {
		return existed, err
	}
	b.Reconcile()
	return existed, nil
}

// SetPaused sets the durable pause state for one instance home. It works
// whether or not the home is currently running.
func (b *Broker) SetPaused(home string, paused bool) error {
	canonical, err := CanonicalHome(home)
	if err != nil {
		return err
	}
	b.mu.Lock()
	runner := b.instances[HomeKey(canonical)]
	b.mu.Unlock()
	if runner != nil {
		runner.setPaused(paused, "command")
		return nil
	}
	return SetPausedInStore(b.cfg.Store, canonical, paused)
}

// SetPausedInStore writes durable pause state without a running daemon. The
// CLI uses it for the socket fallback path.
func SetPausedInStore(store *Store, home string, paused bool) error {
	state, err := store.LoadInstance(home)
	if err != nil {
		return err
	}
	state.Paused = paused
	return store.SaveInstance(state)
}

// Status builds the live status snapshot.
func (b *Broker) Status() Status {
	b.mu.Lock()
	streams := make([]StreamStatus, 0, len(b.streams)+len(b.overBound))
	for _, runner := range b.streams {
		streams = append(streams, runner.snapshot())
	}
	for identityHome := range b.overBound {
		streams = append(streams, StreamStatus{IdentityHome: identityHome, Phase: "over-bound", Admitted: false})
	}
	instances := make([]InstanceStatus, 0, len(b.instances))
	for _, runner := range b.instances {
		instances = append(instances, runner.snapshot())
	}
	b.mu.Unlock()

	sort.SliceStable(streams, func(i, j int) bool { return streams[i].IdentityHome < streams[j].IdentityHome })
	sort.SliceStable(instances, func(i, j int) bool { return instances[i].Home < instances[j].Home })

	return Status{
		UpdatedAt:     b.cfg.Now(),
		StateDir:      b.cfg.Store.Dir(),
		DaemonRunning: true,
		DaemonPID:     os.Getpid(),
		MaxStreams:    b.cfg.MaxStreams,
		Streams:       streams,
		Instances:     instances,
	}
}

func (b *Broker) writeStatus() {
	if err := b.cfg.Store.SaveStatus(b.Status()); err != nil {
		b.cfg.Log("status write failed err=%v", err)
	}
}

// dropExpired removes a registration that never reached a confirmed live
// inspect within the pending expiry, with one log line naming the home and the
// elapsed time (§4).
func (b *Broker) dropExpired(runner *instanceRunner, elapsed time.Duration) {
	b.cfg.Log("expired home=%s pending_for=%s (never reached a confirmed live inspect; server hints are untouched and a later launch is re-raised by the reconnect snapshot)",
		runner.reg.Home, elapsed.Round(time.Second))
	if _, err := b.cfg.Store.DeleteRegistration(runner.reg.Home); err != nil {
		b.cfg.Log("expired home=%s cleanup failed err=%v", runner.reg.Home, err)
	}
	b.mu.Lock()
	delete(b.instances, HomeKey(runner.reg.Home))
	b.mu.Unlock()
	go func() {
		runner.stop()
		b.pruneStreams()
	}()
}

// MaxStreams reports the configured stream bound.
func (b *Broker) MaxStreams() int { return b.cfg.MaxStreams }
