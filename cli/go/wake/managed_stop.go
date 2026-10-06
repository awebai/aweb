package wake

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ManagedReceiver is exported by live status, not inferred from registry files.
// It identifies one accepted owner generation and its complete registration.
type ManagedReceiver struct {
	Registration Registration `json:"registration"`
	Generation   int          `json:"generation"`
	OwnerID      string       `json:"owner_id"`
}

type ManagedStopReceipt struct {
	Version                  int             `json:"version"`
	Scope                    string          `json:"scope"`
	Receiver                 ManagedReceiver `json:"receiver"`
	ManagedJoined            bool            `json:"managed_joined"`
	CompletedAt              time.Time       `json:"completed_at"`
	AcceptedInputDisposition string          `json:"accepted_input_disposition"`
}

const managedStopDeadline = 15 * time.Second

func sameManagedReceiver(a, b ManagedReceiver) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && bytes.Equal(x, y)
}

// NormalizeManagedReceiver validates an exported expectation without accepting
// an absent registration clock or an invented negative generation.
func NormalizeManagedReceiver(expected ManagedReceiver) (ManagedReceiver, error) {
	if expected.OwnerID == "" || expected.Generation < 0 || expected.Registration.RegisteredAt.IsZero() {
		return ManagedReceiver{}, fmt.Errorf("E_WAKE_RECEIVER_MISMATCH: expected live receiver snapshot with owner ID and registration clock")
	}
	r, err := expected.Registration.Normalized()
	if err != nil {
		return ManagedReceiver{}, err
	}
	expected.Registration = r
	return expected, nil
}

// DeregisterManaged requires a currently captured child. Unlike Deregister,
// file-only or absent owners cannot produce a managed completion receipt.
func (b *Broker) DeregisterManaged(ctx context.Context, expected ManagedReceiver) (*ManagedStopReceipt, error) {
	expected, err := NormalizeManagedReceiver(expected)
	if err != nil {
		return nil, err
	}
	// The admission wait is bounded. Once cancellation starts we must retain
	// serialization until join, even if the caller has lost its response.
	for !b.reconcileMu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("E_WAKE_STOP_UNKNOWN: admission: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer b.reconcileMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("E_WAKE_STOP_UNKNOWN: admission: %w", err)
	}
	home := expected.Registration.Home
	key := HomeKey(home)
	b.mu.Lock()
	runner := b.instances[key]
	b.mu.Unlock()
	if runner == nil {
		return nil, fmt.Errorf("E_WAKE_NO_MANAGED_WORKER: no captured receiver for %s", home)
	}
	runner.mu.Lock()
	captured := ManagedReceiver{Registration: runner.reg.clone(), Generation: runner.generation, OwnerID: runner.ownerID}
	child := runner.child
	pending := runner.pendingReg != nil
	runner.mu.Unlock()
	if pending || !sameManagedReceiver(captured, expected) {
		return nil, fmt.Errorf("E_WAKE_RECEIVER_MISMATCH: accepted receiver changed or registration pending")
	}
	durable, exists, loadErr := b.cfg.Store.LoadRegistration(home)
	if loadErr != nil {
		return nil, fmt.Errorf("E_WAKE_RECEIVER_MISMATCH: read registration: %w", loadErr)
	}
	if !exists || !sameManagedReceiver(ManagedReceiver{Registration: durable, Generation: captured.Generation, OwnerID: captured.OwnerID}, captured) {
		return nil, fmt.Errorf("E_WAKE_RECEIVER_MISMATCH: stored registration differs from accepted receiver")
	}
	if child == nil {
		return nil, fmt.Errorf("E_WAKE_NO_MANAGED_WORKER: no captured child for %s", home)
	}
	if !managedProcessGroupsSupported() {
		return nil, fmt.Errorf("E_WAKE_STOP_UNSUPPORTED: owned process-group confirmation unavailable")
	}
	// All expected-receiver checks precede invalidation or stop.
	b.registrationChangedLocked(home)
	b.mu.Lock()
	delete(b.instances, key)
	b.mu.Unlock()
	runner.stop()
	// Keep ordinary stop-before-delete ordering. Even an unconfirmed group
	// must not be relaunched by leaving its registration available to reconcile.
	if _, err := b.cfg.Store.DeleteRegistration(home); err != nil {
		return nil, fmt.Errorf("E_WAKE_STOP_INCOMPLETE: delete: %w", err)
	}
	b.pruneStreamsLocked()
	go b.retryPendingStreams()
	confirmCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := child.confirmManagedStop(confirmCtx); err != nil {
		return nil, fmt.Errorf("E_WAKE_STOP_INCOMPLETE: %w", err)
	}
	return &ManagedStopReceipt{Version: 1, Scope: "captured-managed-worker", Receiver: captured, ManagedJoined: true, CompletedAt: b.cfg.Now().UTC(), AcceptedInputDisposition: "not_certified"}, nil
}

// CallManagedStop never performs file fallback and never accepts legacy OK or
// existed responses. A lost reply is unknown even if the daemon later finishes.
func CallManagedStop(socketPath string, expected ManagedReceiver) (*ManagedStopReceipt, error) {
	return callManagedStop(socketPath, expected, managedStopDeadline)
}

func callManagedStop(socketPath string, expected ManagedReceiver, timeout time.Duration) (*ManagedStopReceipt, error) {
	expected, err := NormalizeManagedReceiver(expected)
	if err != nil {
		return nil, err
	}
	resp, err := callWithTimeout(socketPath, ControlRequest{Op: OpDeregisterManaged, Receiver: &expected}, timeout)
	if err != nil {
		return nil, fmt.Errorf("managed stop NOT confirmed (transport loss may hide completed work): %w", err)
	}
	r := resp.ManagedStop
	if !resp.OK || r == nil || r.Version != 1 || r.Scope != "captured-managed-worker" || !r.ManagedJoined || r.CompletedAt.IsZero() || r.AcceptedInputDisposition != "not_certified" || !sameManagedReceiver(r.Receiver, expected) {
		return nil, fmt.Errorf("E_WAKE_STOP_UNKNOWN: missing or mismatched managed-stop receipt")
	}
	return r, nil
}

func (c *ChannelCoreChild) confirmManagedStop(ctx context.Context) error {
	select {
	case <-c.done:
	default:
		return fmt.Errorf("managed supervisor still running")
	}
	c.mu.Lock()
	groups := append([]int(nil), c.ownedProcessGroups...)
	c.mu.Unlock()
	if len(groups) == 0 {
		return fmt.Errorf("no observed managed process group")
	}
	for _, pgid := range groups {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			gone, err := managedProcessGroupGone(pgid)
			if err != nil {
				return err
			}
			if gone {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	return nil
}
