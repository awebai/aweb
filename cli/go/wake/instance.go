package wake

import (
	"context"
	"os"
	"sync"

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

	mu           sync.Mutex
	state        InstanceState
	admitted     map[string]bool
	events       chan eventOffer
	child        *ChannelCoreChild
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
	event   awid.AgentEvent
	binding ReceiveIdentity
}

func newInstanceRunner(b *Broker, reg Registration, state InstanceState) *instanceRunner {
	return &instanceRunner{
		broker:   b,
		reg:      reg,
		state:    state,
		admitted: map[string]bool{},
		events:   make(chan eventOffer, 256),
		done:     make(chan struct{}),
	}
}

func (r *instanceRunner) start(ctx context.Context) {
	r.startOnce.Do(func() {
		ctx, r.cancel = context.WithCancel(ctx)
		go r.run(ctx)
	})
}

func (r *instanceRunner) updateRegistration(reg Registration) {
	r.mu.Lock()
	r.reg = reg
	if r.admitted == nil {
		r.admitted = map[string]bool{}
	}
	needed := map[string]struct{}{}
	for _, binding := range reg.ReceiveBindings() {
		needed[binding.IdentityHome] = struct{}{}
	}
	for identityHome := range r.admitted {
		if _, ok := needed[identityHome]; !ok {
			delete(r.admitted, identityHome)
		}
	}
	r.mu.Unlock()
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

func (r *instanceRunner) bindingForIdentityHome(identityHome string) (ReceiveIdentity, bool) {
	if r.conflictHome != "" {
		return ReceiveIdentity{}, false
	}
	return r.registrationSnapshot().BindingForIdentityHome(identityHome)
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
	if r.broker.cfg.ChannelCore != nil {
		awCommand, _ := os.Executable()
		r.child = r.broker.cfg.ChannelCore.StartChild(ctx, r.registrationSnapshot(), channelCoreChildConfig{
			Coalesce: r.broker.cfg.Coalesce, RateLimit: r.broker.cfg.RateLimit, InspectDelay: r.broker.cfg.PollInterval,
			OatsBin: session.DefaultOatsBin, AWCommand: awCommand, AdmissionSize: 256, Log: r.broker.cfg.Log,
			OnInactive: func(state string) {
				r.mu.Lock()
				r.state.Inactive = true
				r.state.LastState = state
				r.mu.Unlock()
				r.persist()
			},
		})
		defer r.child.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			r.persist()
			return
		case offer := <-r.events:
			if r.child != nil {
				r.child.Offer(offer.binding, offer.event)
			}
		}
	}
}

// offerEvent queues an event for the channel-core child. It never blocks the stream goroutine.
func (r *instanceRunner) offerEvent(ev awid.AgentEvent, binding ReceiveIdentity) {
	select {
	case r.events <- eventOffer{event: ev, binding: binding}:
	default:
		r.mu.Lock()
		r.state.Evicted++
		r.mu.Unlock()
		select {
		case <-r.events:
		default:
		}
		select {
		case r.events <- eventOffer{event: ev, binding: binding}:
		default:
		}
	}
}

func (r *instanceRunner) setPaused(paused bool, source string) {
	r.mu.Lock()
	changed := r.state.Paused != paused
	r.state.Paused = paused
	child := r.child
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

func (r *instanceRunner) setStreamAdmitted(identityHome string, admitted bool) {
	r.mu.Lock()
	if r.admitted == nil {
		r.admitted = map[string]bool{}
	}
	r.admitted[identityHome] = admitted
	r.mu.Unlock()
}

func (r *instanceRunner) streamAdmitted(identityHome string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.admitted[identityHome]
}

func (r *instanceRunner) allStreamsAdmitted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, binding := range r.reg.ReceiveBindings() {
		if !r.admitted[binding.IdentityHome] {
			return false
		}
	}
	return true
}

func (r *instanceRunner) persist() {
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if err := r.broker.cfg.Store.SaveInstance(state); err != nil {
		r.broker.cfg.Log("state write failed home=%s err=%v", r.home(), err)
	}
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
	receive := []ReceiveIdentityStatus{}
	allAdmitted := true
	for _, binding := range r.reg.ReceiveBindings() {
		admitted := r.admitted[binding.IdentityHome]
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
	return InstanceStatus{
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
		ChannelCore:         r.child.Status(),
		ConflictHome:        r.conflictHome,
	}
}
