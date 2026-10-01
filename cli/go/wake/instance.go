package wake

import (
	"context"
	"os"
	"reflect"
	"sync"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/wake/session"
)

// instanceRunner owns one registered instance: its durable state, its inspect
// poll, and its submissions. One goroutine per instance is what makes "one
// submission is in flight at a time" (§4) true by construction rather than by
// a lock somebody has to remember to take.
type instanceRunner struct {
	broker *Broker
	reg    Registration

	persistMu    sync.Mutex
	mu           sync.Mutex
	state        InstanceState
	admitted     map[string]bool
	generation   int
	events       chan eventOffer
	updates      chan Registration
	inactive     chan inactiveSignal
	reactivate   chan reactivateRequest
	pauses       chan pauseRequest
	child        *ChannelCoreChild
	pendingReg   *Registration
	conflictHome string
	cancel       context.CancelFunc
	done         chan struct{}
	// startOnce keeps a registration reconciled before Broker.Run from being
	// launched twice once the daemon context becomes available.
	startOnce sync.Once
	// stopOnce keeps stop() safe to call from the reconcile path and the
	// expiry path at the same time.
	stopOnce sync.Once
}

type eventOffer struct {
	event      awid.AgentEvent
	binding    ReceiveIdentity
	generation int
}

type inactiveSignal struct {
	generation int
	state      string
}

type pauseRequest struct {
	paused bool
	source string
	done   chan struct{}
}

type reactivateRequest struct {
	done chan struct{}
}

func newInstanceRunner(b *Broker, reg Registration, state InstanceState) *instanceRunner {
	return &instanceRunner{
		broker:     b,
		reg:        reg,
		state:      state,
		admitted:   map[string]bool{},
		events:     make(chan eventOffer, 256),
		updates:    make(chan Registration, 1),
		inactive:   make(chan inactiveSignal, 1),
		reactivate: make(chan reactivateRequest, 1),
		pauses:     make(chan pauseRequest, 16),
		done:       make(chan struct{}),
	}
}

func (r *instanceRunner) start(ctx context.Context) {
	r.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(ctx)
		r.mu.Lock()
		r.cancel = cancel
		r.mu.Unlock()
		go r.run(ctx)
	})
}

func (r *instanceRunner) updateRegistration(reg Registration) bool {
	r.mu.Lock()
	changed := !sameReceiveBindings(r.reg.ReceiveBindings(), reg.ReceiveBindings())
	started := r.cancel != nil
	if !started || !changed {
		r.publishRegistrationLocked(reg, changed)
		r.mu.Unlock()
		if changed {
			r.persist()
		}
		return false
	}
	pending := reg.clone()
	r.pendingReg = &pending
	r.mu.Unlock()
	select {
	case r.updates <- reg:
	default:
		select {
		case <-r.updates:
		default:
		}
		r.updates <- reg
	}
	return true
}

func (r *instanceRunner) publishRegistrationLocked(reg Registration, bumpGeneration bool) {
	r.reg = reg
	if bumpGeneration {
		r.resetLifecycleLocked()
		r.generation++
	}
	if r.admitted == nil {
		r.admitted = map[string]bool{}
	}
	needed := map[string]struct{}{}
	for _, binding := range reg.ReceiveBindings() {
		if key, err := bindingKey(binding.IdentityHome, binding.TeamID); err == nil {
			needed[key] = struct{}{}
		}
	}
	for key := range r.admitted {
		if _, ok := needed[key]; !ok {
			delete(r.admitted, key)
		}
	}
}

func sameReceiveBindings(left, right []ReceiveIdentity) bool {
	if len(left) != len(right) {
		return false
	}
	leftKeys := make([]string, 0, len(left))
	rightKeys := make([]string, 0, len(right))
	for _, binding := range left {
		leftKeys = append(leftKeys, bindingID(binding))
	}
	for _, binding := range right {
		rightKeys = append(rightKeys, bindingID(binding))
	}
	return reflect.DeepEqual(leftKeys, rightKeys)
}

func (r *instanceRunner) setConflictHome(home string) {
	r.mu.Lock()
	r.conflictHome = home
	r.mu.Unlock()
}

func (r *instanceRunner) reactivateRegistration() {
	r.mu.Lock()
	// Binding updates reactivate when published. An identical active hook retry
	// must not interrupt input or reset liveness.
	if !r.state.Inactive || r.pendingReg != nil {
		r.mu.Unlock()
		return
	}
	started := r.cancel != nil
	if !started {
		r.resetLifecycleLocked()
		r.generation++
		r.mu.Unlock()
		r.persist()
		return
	}
	r.mu.Unlock()
	done := make(chan struct{})
	req := reactivateRequest{done: done}
	select {
	case r.reactivate <- req:
		select {
		case <-done:
		case <-r.done:
		}
	case <-r.done:
	}
}

func (r *instanceRunner) resetLifecycleLocked() {
	r.state.FirstPresentAt = time.Time{}
	r.state.Inactive = false
	r.state.LastInspectAt = time.Time{}
	r.state.LastState = ""
	r.state.LastError = ""
	r.state.UnreadCount = 0
}

func (r *instanceRunner) registrationSnapshot() Registration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reg.clone()
}

func (r *instanceRunner) home() string {
	return r.registrationSnapshot().Home
}

func (r *instanceRunner) receiveBindings() []ReceiveIdentity {
	return r.registrationSnapshot().ReceiveBindings()
}

func (r *instanceRunner) pendingReceiveBindings() []ReceiveIdentity {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pendingReg == nil {
		return nil
	}
	return r.pendingReg.ReceiveBindings()
}

func (r *instanceRunner) hasPendingRegistration() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pendingReg != nil
}

func (r *instanceRunner) bindingForStreamKey(key string) (ReceiveIdentity, int, bool) {
	r.mu.Lock()
	if r.conflictHome != "" {
		r.mu.Unlock()
		return ReceiveIdentity{}, 0, false
	}
	reg := r.reg.clone()
	generation := r.generation
	r.mu.Unlock()
	for _, binding := range reg.ReceiveBindings() {
		if got, err := bindingKey(binding.IdentityHome, binding.TeamID); err == nil && got == key {
			return binding, generation, true
		}
	}
	return ReceiveIdentity{}, 0, false
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
	var child *ChannelCoreChild
	startChild := func() {
		if r.broker.cfg.ChannelCore == nil {
			return
		}
		r.mu.Lock()
		inactive := r.state.Inactive
		paused := r.state.Paused
		reg := r.reg.clone()
		generation := r.generation
		r.mu.Unlock()
		if inactive {
			return
		}
		awCommand, _ := os.Executable()
		oatsBin := (&session.ExecClient{}).ResolveBin()
		if resolver, ok := r.broker.cfg.Session.(interface{ ResolveBin() string }); ok {
			oatsBin = resolver.ResolveBin()
		}
		newChild := r.broker.cfg.ChannelCore.StartChild(ctx, reg, channelCoreChildConfig{
			Coalesce: r.broker.cfg.Coalesce, RateLimit: r.broker.cfg.RateLimit, InspectDelay: r.broker.cfg.PollInterval,
			OatsBin: oatsBin, AWCommand: awCommand, AdmissionSize: 256, Paused: paused, Generation: generation, Log: r.broker.cfg.Log,
			OnLiveness: func(at time.Time, state, inspectErr string) {
				r.recordChildLiveness(generation, at, state, inspectErr)
			},
			OnInactive: func(state string) {
				select {
				case r.inactive <- inactiveSignal{generation: generation, state: state}:
				default:
				}
			},
		})
		r.mu.Lock()
		r.child = newChild
		r.mu.Unlock()
		child = newChild
	}
	stopChild := func() {
		if child == nil {
			return
		}
		child.Stop()
		r.mu.Lock()
		if r.child == child {
			r.child = nil
		}
		r.mu.Unlock()
		child = nil
	}
	startChild()
	defer stopChild()
	for {
		select {
		case <-ctx.Done():
			r.persist()
			return
		case signal := <-r.inactive:
			r.mu.Lock()
			currentGeneration := r.generation
			if signal.generation != currentGeneration {
				r.mu.Unlock()
				r.broker.cfg.Log("inactive ignored home=%s generation=%d current_generation=%d state=%s", r.home(), signal.generation, currentGeneration, signal.state)
				continue
			}
			r.state.Inactive = true
			r.state.LastState = signal.state
			r.mu.Unlock()
			r.persist()
			stopChild()
		case req := <-r.pauses:
			r.applyPause(req.paused, req.source, child)
			close(req.done)
		case req := <-r.reactivate:
			r.mu.Lock()
			inactive := r.state.Inactive
			r.mu.Unlock()
			if !inactive {
				close(req.done)
				continue
			}
			stopChild()
			r.mu.Lock()
			r.resetLifecycleLocked()
			r.generation++
			r.mu.Unlock()
			r.persist()
			startChild()
			close(req.done)
			go r.broker.admitCurrentRunnerStreams(r)
		case reg := <-r.updates:
			stopChild()
			r.mu.Lock()
			r.publishRegistrationLocked(reg, true)
			r.pendingReg = nil
			r.mu.Unlock()
			r.persist()
			startChild()
			go func() {
				r.broker.admitCurrentRunnerStreams(r)
				r.broker.pruneStreams()
			}()
		case offer := <-r.events:
			r.mu.Lock()
			inactive := r.state.Inactive
			currentGeneration := r.generation
			bindingAllowed := r.reg.hasBinding(offer.binding)
			if inactive || offer.generation != currentGeneration || !bindingAllowed {
				r.state.Evicted++
			}
			r.mu.Unlock()
			if inactive {
				r.broker.cfg.Log("event dropped home=%s reason=inactive message_id=%s session_id=%s", r.home(), offer.event.MessageID, offer.event.SessionID)
				continue
			}
			if offer.generation != currentGeneration || !bindingAllowed {
				r.broker.cfg.Log("event dropped home=%s reason=stale_binding generation=%d current_generation=%d message_id=%s session_id=%s", r.home(), offer.generation, currentGeneration, offer.event.MessageID, offer.event.SessionID)
				continue
			}
			if child != nil {
				child.Offer(offer.binding, offer.event)
			}
		}
	}
}

// offerEvent queues an event for the channel-core child. It never blocks the stream goroutine.
func (r *instanceRunner) offerEvent(ev awid.AgentEvent, binding ReceiveIdentity, generation int) {
	r.mu.Lock()
	inactive := r.state.Inactive
	currentGeneration := r.generation
	bindingAllowed := r.reg.hasBinding(binding)
	if inactive || generation != currentGeneration || !bindingAllowed {
		r.state.Evicted++
	}
	r.mu.Unlock()
	if inactive {
		r.broker.cfg.Log("event dropped home=%s reason=inactive message_id=%s session_id=%s", r.home(), ev.MessageID, ev.SessionID)
		return
	}
	if generation != currentGeneration || !bindingAllowed {
		r.broker.cfg.Log("event dropped home=%s reason=stale_binding generation=%d current_generation=%d message_id=%s session_id=%s", r.home(), generation, currentGeneration, ev.MessageID, ev.SessionID)
		return
	}
	select {
	case r.events <- eventOffer{event: ev, binding: binding, generation: generation}:
	default:
		r.mu.Lock()
		r.state.Evicted++
		r.mu.Unlock()
		select {
		case <-r.events:
		default:
		}
		select {
		case r.events <- eventOffer{event: ev, binding: binding, generation: generation}:
		default:
		}
	}
}

func (r *instanceRunner) setPaused(paused bool, source string) {
	r.mu.Lock()
	started := r.cancel != nil
	r.mu.Unlock()
	if !started {
		r.applyPause(paused, source, nil)
		return
	}
	done := make(chan struct{})
	req := pauseRequest{paused: paused, source: source, done: done}
	select {
	case r.pauses <- req:
		select {
		case <-done:
		case <-r.done:
		}
	case <-r.done:
	}
}

func (r *instanceRunner) recordRegistrationError(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	r.state.LastError = err.Error()
	r.mu.Unlock()
	r.persist()
}

func (r *instanceRunner) recordChildLiveness(generation int, at time.Time, state, inspectErr string) {
	r.mu.Lock()
	if generation != r.generation {
		r.mu.Unlock()
		return
	}
	changed := false
	if state != "" || inspectErr != "" {
		r.state.LastInspectAt = at
		changed = true
	}
	if state != "" {
		r.state.LastState = state
		if state != "not-launched" && r.state.FirstPresentAt.IsZero() {
			r.state.FirstPresentAt = at
		}
		if inspectErr == "" && r.state.LastError != "" {
			r.state.LastError = ""
		}
	}
	if inspectErr != "" {
		r.state.LastError = inspectErr
		changed = true
	}
	r.mu.Unlock()
	if changed {
		r.persist()
	}
}

func (r *instanceRunner) applyPause(paused bool, source string, child *ChannelCoreChild) {
	r.mu.Lock()
	changed := r.state.Paused != paused
	r.state.Paused = paused
	if child == nil {
		child = r.child
	}
	r.mu.Unlock()
	if child != nil {
		child.Pause(paused)
	}
	if changed {
		verb := "resumed"
		if paused {
			verb = "paused"
		}
		r.broker.cfg.Log("%s home=%s source=%s", verb, r.home(), source)
	}
	r.persist()
}

func (r *instanceRunner) setStreamAdmitted(binding ReceiveIdentity, admitted bool) {
	key, err := bindingKey(binding.IdentityHome, binding.TeamID)
	if err != nil {
		return
	}
	r.mu.Lock()
	if r.admitted == nil {
		r.admitted = map[string]bool{}
	}
	r.admitted[key] = admitted
	r.mu.Unlock()
}

func (r *instanceRunner) streamAdmitted(binding ReceiveIdentity) bool {
	key, err := bindingKey(binding.IdentityHome, binding.TeamID)
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.admitted[key]
}

func (r *instanceRunner) allStreamsAdmitted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, binding := range r.reg.ReceiveBindings() {
		key, err := bindingKey(binding.IdentityHome, binding.TeamID)
		if err != nil || !r.admitted[key] {
			return false
		}
	}
	return true
}

func (r *instanceRunner) persist() {
	// Serialize before taking the snapshot, so an old write cannot land last.
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if err := r.broker.cfg.Store.SaveInstance(state); err != nil {
		r.broker.cfg.Log("state write failed home=%s err=%v", r.home(), err)
	}
}

func (r *instanceRunner) snapshot() InstanceStatus {
	r.mu.Lock()
	phase := PhasePending
	switch {
	case r.state.Inactive:
		phase = PhaseInactive
	case r.state.ConfirmedLive():
		phase = PhaseActive
	}
	receive := []ReceiveIdentityStatus{}
	allAdmitted := true
	for _, binding := range r.reg.ReceiveBindings() {
		key, err := bindingKey(binding.IdentityHome, binding.TeamID)
		admitted := err == nil && r.admitted[key]
		if !admitted {
			allAdmitted = false
		}
		receive = append(receive, ReceiveIdentityStatus{
			IdentityHome:   binding.IdentityHome,
			TeamID:         binding.TeamID,
			Label:          binding.Label,
			DeliveryOwner:  binding.DeliveryOwner,
			EventClasses:   append([]string(nil), binding.EventClasses...),
			Controls:       binding.Controls,
			StreamAdmitted: admitted,
		})
	}
	child := r.child
	status := InstanceStatus{
		Home:                r.reg.Home,
		IdentityHome:        r.reg.IdentityHome,
		RuntimeDelivery:     r.reg.RuntimeDelivery,
		PrimaryIdentityHome: r.reg.PrimaryIdentityHome,
		ReceiveIdentities:   receive,
		Backend:             r.reg.Backend,
		Delivery:            r.reg.Delivery,
		RegisteredAt:        r.reg.RegisteredAt,
		Phase:               phase,
		Paused:              r.state.Paused,
		Evicted:             r.state.Evicted,
		LastInspectAt:       r.state.LastInspectAt,
		LastState:           r.state.LastState,
		LastError:           r.state.LastError,
		UnreadCount:         r.state.UnreadCount,
		StreamAdmitted:      allAdmitted,
		ConflictHome:        r.conflictHome,
	}
	r.mu.Unlock()
	if child != nil {
		status.ChannelCore = child.Status()
	}
	return status
}
