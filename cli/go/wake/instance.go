package wake

import (
	"context"
	"sync"
	"time"

	"github.com/awebai/aw/wake/session"
)

// instanceRunner owns one registered instance: its durable state, its inspect
// poll, and its submissions. One goroutine per instance is what makes "one
// submission is in flight at a time" (§4) true by construction rather than by
// a lock somebody has to remember to take.
type instanceRunner struct {
	broker *Broker
	reg    Registration

	mu       sync.Mutex
	state    InstanceState
	admitted bool
	// nextProbe throttles inspects for an instance with nothing pending, so a
	// hundred idle instances do not exec `oats` fifty times a second.
	nextProbe time.Time

	hints  chan hintOffer
	cancel context.CancelFunc
	done   chan struct{}
	// stopOnce keeps stop() safe to call from the reconcile path and the
	// expiry path at the same time.
	stopOnce sync.Once
}

type hintOffer struct {
	hint   Hint
	unread int
}

func newInstanceRunner(b *Broker, reg Registration, state InstanceState) *instanceRunner {
	return &instanceRunner{
		broker: b,
		reg:    reg,
		state:  state,
		hints:  make(chan hintOffer, 256),
		done:   make(chan struct{}),
	}
}

func (r *instanceRunner) start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)
	go r.run(ctx)
}

// stop is safe to call more than once, and safe to call on a runner that was
// never started — the expiry path and the reconcile path can both reach it.
func (r *instanceRunner) stop() {
	r.stopOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
			return
		}
		close(r.done)
	})
	<-r.done
}

func (r *instanceRunner) run(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.broker.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.persist()
			return
		case offer := <-r.hints:
			r.absorb(offer)
			// A new hint may be immediately actionable; the coalescing window
			// is enforced inside evaluate.
			r.evaluate(ctx)
		case <-ticker.C:
			r.evaluate(ctx)
		}
	}
}

// offer queues a hint for this instance. It never blocks the stream goroutine:
// a full channel drops the *oldest* offer rather than stalling every other
// instance on one wedged runner, and the drop is counted as an eviction so it
// is visible in status.
func (r *instanceRunner) offer(h Hint, unread int) {
	select {
	case r.hints <- hintOffer{hint: h, unread: unread}:
	default:
		select {
		case <-r.hints:
		default:
		}
		r.mu.Lock()
		r.state.Evicted++
		r.mu.Unlock()
		select {
		case r.hints <- hintOffer{hint: h, unread: unread}:
		default:
		}
	}
}

func (r *instanceRunner) absorb(offer hintOffer) {
	r.mu.Lock()
	before := r.state.Evicted
	added := r.state.AddHint(offer.hint, r.broker.cfg.HintCap)
	evicted := r.state.Evicted - before
	if offer.unread > 0 {
		r.state.UnreadCount = offer.unread
	}
	pending := len(r.state.Pending)
	r.mu.Unlock()

	if evicted > 0 {
		r.broker.cfg.Log("hints evicted home=%s evicted=%d cap=%d pending=%d", r.reg.Home, evicted, r.broker.cfg.HintCap, pending)
	}
	if added && !offer.hint.Transient {
		r.persist()
	}
}

func (r *instanceRunner) setPaused(paused bool, source string) {
	r.mu.Lock()
	changed := r.state.Paused != paused
	r.state.Paused = paused
	r.mu.Unlock()
	if changed {
		verb := "resumed"
		if paused {
			verb = "paused"
		}
		r.broker.cfg.Log("%s home=%s source=%s", verb, r.reg.Home, source)
	}
	r.persist()
}

func (r *instanceRunner) setStreamAdmitted(admitted bool) {
	r.mu.Lock()
	r.admitted = admitted
	r.mu.Unlock()
}

func (r *instanceRunner) streamAdmitted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.admitted
}

func (r *instanceRunner) persist() {
	r.mu.Lock()
	state := r.state
	pending := make([]Hint, len(state.Pending))
	copy(pending, state.Pending)
	state.Pending = pending
	r.mu.Unlock()
	if err := r.broker.cfg.Store.SaveInstance(state); err != nil {
		r.broker.cfg.Log("state write failed home=%s err=%v", r.reg.Home, err)
	}
}

// evaluate is one policy step for this instance.
func (r *instanceRunner) evaluate(ctx context.Context) {
	cfg := r.broker.cfg
	now := cfg.Now()

	r.mu.Lock()
	state := r.state
	nextProbe := r.nextProbe
	r.mu.Unlock()

	if state.Inactive {
		return
	}

	// A registration that never reached a confirmed live inspect is dropped at
	// the pending expiry, with one log line. It deletes no server messages.
	if !state.ConfirmedLive() {
		if elapsed := now.Sub(r.reg.RegisteredAt); r.reg.RegisteredAt.After(time.Time{}) && elapsed >= cfg.PendingExpiry {
			r.broker.dropExpired(r, elapsed)
			return
		}
	}

	pending := state.Pending
	coalesced := len(pending) > 0 && now.Sub(oldestHintAt(pending)) >= cfg.Coalesce
	rateLimitElapsed := state.LastAttemptAt.IsZero() || now.Sub(state.LastAttemptAt) >= cfg.RateLimit
	wouldSubmit := !state.Paused && coalesced && rateLimitElapsed

	// Inspect when it can change something: before the first confirmed live
	// observation, when a submission is otherwise ready, or on the idle probe
	// that notices a stopped instance.
	if state.ConfirmedLive() && !wouldSubmit && now.Before(nextProbe) {
		return
	}

	inspection, err := cfg.Session.Inspect(ctx, r.reg.Home)

	r.mu.Lock()
	r.state.LastInspectAt = now
	r.nextProbe = now.Add(cfg.IdleProbe)
	if err != nil {
		r.state.LastError = err.Error()
		confirmed := r.state.ConfirmedLive()
		r.mu.Unlock()
		r.persist()
		if !confirmed {
			// Before the first confirmed live inspect, every pending state and
			// every error is tolerated and nothing is concluded from either
			// (§4). E_RUNTIME_ENDPOINT_UNKNOWN is the expected one.
			return
		}
		// After confirmation, an unanswerable backend is retried and reported.
		// It is never treated as an absent instance, because that would mark a
		// live agent inactive and stop its wakes (§6).
		cfg.Log("inspect failed home=%s code=%s err=%v", r.reg.Home, orDash(session.ErrorCode(err)), err)
		return
	}
	r.state.LastError = ""
	r.state.LastState = inspection.RawState
	firstPresence := false
	if inspection.Present && !r.state.ConfirmedLive() {
		r.state.FirstPresentAt = now
		firstPresence = true
	}
	confirmed := r.state.ConfirmedLive()
	paused := r.state.Paused
	pending = append([]Hint(nil), r.state.Pending...)
	lastAttempt := r.state.LastAttemptAt
	r.mu.Unlock()

	if firstPresence {
		cfg.Log("present home=%s backend=%s state=%s", r.reg.Home, orDash(inspection.Backend), orDash(inspection.RawState))
	}

	action := ActionFor(leadingIntent(pending), inspection.State, confirmed)
	if action != ActionInactive && confirmed && !inspection.Present {
		// Present:false without a `stopped` state is not a verdict — an
		// unavailable backend is never proof that an instance is gone (§6).
		// Hold and re-evaluate on the next poll.
		r.persist()
		return
	}
	switch action {
	case ActionInactive:
		r.mu.Lock()
		r.state.Inactive = true
		r.mu.Unlock()
		r.persist()
		cfg.Log("inactive home=%s state=%s (registration kept; removal belongs to the retire hook)", r.reg.Home, orDash(inspection.RawState))
		return
	case ActionWaitPending, ActionDefer:
		r.persist()
		return
	}

	// ActionSubmit. Everything below is a bound on how often, never a
	// suppression of what: nothing here marks an item presented.
	if paused {
		r.persist()
		return
	}
	if len(pending) == 0 {
		r.persist()
		return
	}
	if now.Sub(oldestHintAt(pending)) < cfg.Coalesce {
		r.persist()
		return
	}
	if !lastAttempt.IsZero() && now.Sub(lastAttempt) < cfg.RateLimit {
		r.persist()
		return
	}

	text := Compose(pending)
	inputErr := cfg.Session.Input(ctx, r.reg.Home, text)

	r.mu.Lock()
	r.state.LastAttemptAt = now
	if inputErr == nil {
		r.state.LastSubmitAt = now
		r.state.Pending = removeHints(r.state.Pending, pending)
		r.state.LastError = ""
	} else {
		r.state.LastError = inputErr.Error()
	}
	r.mu.Unlock()
	r.persist()

	if inputErr != nil {
		// `oats session input` refused, or the backend was unreachable:
		// nothing was typed, the hints stay pending, and the registration is
		// reconciled on the next inspect (§6).
		cfg.Log("submit failed home=%s hints=%d code=%s err=%v", r.reg.Home, len(pending), orDash(session.ErrorCode(inputErr)), inputErr)
		return
	}
	cfg.Log("submitted home=%s hints=%d state=%s (delivery only; nothing was acknowledged and nothing is marked presented)",
		r.reg.Home, len(pending), orDash(inspection.RawState))
}

func oldestHintAt(hints []Hint) time.Time {
	oldest := time.Time{}
	for _, h := range hints {
		if oldest.IsZero() || h.At.Before(oldest) {
			oldest = h.At
		}
	}
	return oldest
}

// leadingIntent is the intent of the batch's highest band, used only to pick
// the row of the state table; every row currently has the same actions.
func leadingIntent(hints []Hint) Intent {
	best := IntentAmbient
	bestRank := 99
	for _, h := range hints {
		if rank := batchRank(h); rank < bestRank {
			bestRank = rank
			best = h.Intent
		}
	}
	return best
}

// removeHints drops the submitted set from pending, keeping anything that
// arrived while the submission was in flight.
func removeHints(pending, submitted []Hint) []Hint {
	if len(submitted) == 0 {
		return pending
	}
	drop := make(map[string]struct{}, len(submitted))
	for _, h := range submitted {
		drop[h.DedupeKey()] = struct{}{}
	}
	out := pending[:0:0]
	for _, h := range pending {
		if _, ok := drop[h.DedupeKey()]; ok {
			continue
		}
		out = append(out, h)
	}
	return out
}

func (r *instanceRunner) snapshot() InstanceStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	phase := PhasePending
	switch {
	case r.state.Inactive:
		phase = PhaseInactive
	case r.state.ConfirmedLive():
		phase = PhaseActive
	}
	return InstanceStatus{
		Home:           r.reg.Home,
		IdentityHome:   r.reg.IdentityHome,
		Backend:        r.reg.Backend,
		Delivery:       r.reg.Delivery,
		RegisteredAt:   r.reg.RegisteredAt,
		Phase:          phase,
		Paused:         r.state.Paused,
		PendingHints:   len(r.state.Pending),
		Evicted:        r.state.Evicted,
		LastInspectAt:  r.state.LastInspectAt,
		LastAttemptAt:  r.state.LastAttemptAt,
		LastSubmitAt:   r.state.LastSubmitAt,
		LastState:      r.state.LastState,
		LastError:      r.state.LastError,
		UnreadCount:    r.state.UnreadCount,
		StreamAdmitted: r.admitted,
	}
}
