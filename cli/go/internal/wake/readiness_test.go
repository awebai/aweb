package wake

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func readinessEvidence(t *testing.T) ReadinessInput {
	t.Helper()
	home := t.TempDir()
	identityHome := filepath.Join(home, ".aw")
	if err := os.Mkdir(identityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	registration, err := (Registration{Home: home, IdentityHome: identityHome, Delivery: DeliverySession}).Normalized()
	if err != nil {
		t.Fatal(err)
	}
	row := InstanceStatus{Home: registration.Home, IdentityHome: registration.IdentityHome, Delivery: registration.Delivery, RuntimeDelivery: registration.RuntimeDelivery, Phase: PhaseActive, ChannelCore: ChannelCoreStatus{Running: true, ReadinessState: "unknown", ReadinessWaiting: "inspect_done"}}
	now := time.Now().UTC()
	row.LastInspectAt = now
	for _, binding := range registration.ReceiveBindings() {
		row.ReceiveIdentities = append(row.ReceiveIdentities, ReceiveIdentityStatus{IdentityHome: binding.IdentityHome, TeamID: binding.TeamID, Label: binding.Label, Controls: binding.Controls, DeliveryOwner: binding.DeliveryOwner, EventClasses: binding.EventClasses, StreamAdmitted: true, StreamPhase: string(StreamLive)})
	}
	return ReadinessInput{Home: registration.Home, Registration: &registration, Status: Status{UpdatedAt: now, DaemonRunning: true, DaemonVersion: "1.36.59", Instances: []InstanceStatus{row}}, MinimumDaemonVersion: "1.36.13", Now: now}
}

func TestReadinessRequiresIndependentDaemonRegistrationStreamAndWorkerEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		code   ReadinessCode
		change func(*ReadinessInput)
	}{
		{"unavailable control is not absence", ReadinessDaemonUnavailable, func(in *ReadinessInput) { in.ControlError = errors.New("control response lost") }},
		{"stopped daemon", ReadinessDaemonNotRunning, func(in *ReadinessInput) { in.Status.DaemonRunning = false }},
		{"missing listener and no daemon lock", ReadinessDaemonNotRunning, func(in *ReadinessInput) {
			in.Status.DaemonRunning = false
			in.ControlError = ErrDaemonDown
		}},
		{"missing listener with daemon lock held", ReadinessDaemonUnavailable, func(in *ReadinessInput) { in.ControlError = ErrDaemonDown }},
		{"failed exchange without daemon lock", ReadinessDaemonUnavailable, func(in *ReadinessInput) {
			in.Status.DaemonRunning = false
			in.ControlError = errors.New("control response lost")
		}},
		{"unreported daemon version", ReadinessVersionUnknown, func(in *ReadinessInput) { in.Status.DaemonVersion = "" }},
		{"old daemon", ReadinessDaemonOutdated, func(in *ReadinessInput) { in.Status.DaemonVersion = "1.36.12" }},
		{"missing registration", ReadinessHomeNotRegistered, func(in *ReadinessInput) { in.Registration = nil }},
		{"different identity target", ReadinessRegistrationMismatch, func(in *ReadinessInput) { in.Status.Instances[0].IdentityHome = t.TempDir() }},
		{"different receive controls", ReadinessRegistrationMismatch, func(in *ReadinessInput) { in.Status.Instances[0].ReceiveIdentities[0].Controls = false }},
		{"different delivery owner", ReadinessRegistrationMismatch, func(in *ReadinessInput) { in.Status.Instances[0].ReceiveIdentities[0].DeliveryOwner = "other" }},
		{"different receive labels", ReadinessRegistrationMismatch, func(in *ReadinessInput) { in.Status.Instances[0].ReceiveIdentities[0].Label = "other" }},
		{"foreign grant", ReadinessForeignGrant, func(in *ReadinessInput) { in.ForeignGrantHome = "/other/grant" }},
		{"disconnected stream", ReadinessStreamDisconnected, func(in *ReadinessInput) {
			in.Status.Instances[0].ReceiveIdentities[0].StreamPhase = string(StreamRetrying)
		}},
		{"stopped worker", ReadinessWorkerNotRunning, func(in *ReadinessInput) { in.Status.Instances[0].ChannelCore.Running = false }},
		{"worker error", ReadinessWorkerError, func(in *ReadinessInput) { in.Status.Instances[0].ChannelCore.LastError = "failed" }},
		{"binding error", ReadinessBindingError, func(in *ReadinessInput) {
			in.Status.Instances[0].ChannelCore.BindingErrors = map[string]string{"binding": "failed"}
		}},
		{"paused receiver", ReadinessPaused, func(in *ReadinessInput) { in.Status.Instances[0].Paused = true }},
		{"failed inspection", ReadinessInspectionError, func(in *ReadinessInput) { in.Status.Instances[0].ChannelCore.ReadinessWaiting = "inspect_error" }},
		{"shell endpoint", ReadinessEndpointUnusable, func(in *ReadinessInput) { in.Status.Instances[0].ChannelCore.ReadinessState = "shell" }},
		{"permission modal", ReadinessSessionWaiting, func(in *ReadinessInput) { in.Status.Instances[0].ChannelCore.ReadinessState = "blocked" }},
		{"missing status timestamp", ReadinessTimestampUnknown, func(in *ReadinessInput) { in.Status.UpdatedAt = time.Time{} }},
		{"future snapshot", ReadinessObservationInvalid, func(in *ReadinessInput) { in.Status.UpdatedAt = in.Now.Add(time.Second) }},
		{"inspect after snapshot", ReadinessObservationInvalid, func(in *ReadinessInput) { in.Status.UpdatedAt = in.Now.Add(-time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := readinessEvidence(t)
			if got := EvaluateReadiness(input); !got.Ready || got.Code != Ready {
				t.Fatalf("valid neighbor: %#v", got)
			}
			test.change(&input)
			got := EvaluateReadiness(input)
			if got.Ready || got.Code != test.code || got.Reason == "" {
				t.Fatalf("readiness=%#v want %s", got, test.code)
			}
		})
	}
}

func TestReadinessOldOrPendingObservationIsAdvisoryWithoutForcedInspection(t *testing.T) {
	input := readinessEvidence(t)
	input.Status.UpdatedAt = input.Now.Add(-time.Hour)
	input.Status.Instances[0].LastInspectAt = input.Status.UpdatedAt
	input.Status.Instances[0].ChannelCore.ReadinessWaiting = "inspect_start"
	got := EvaluateReadiness(input)
	if !got.Ready || !slices.Contains(got.Advisories, ReadinessObservationAged) || !slices.Contains(got.Advisories, ReadinessInspectionPending) {
		t.Fatalf("idle observation wrongly refused: %#v", got)
	}
	input.Status.Instances[0].LastInspectAt = time.Time{}
	input.Status.Instances[0].ChannelCore.ReadinessWaiting = ""
	got = EvaluateReadiness(input)
	if !got.Ready || !slices.Contains(got.Advisories, ReadinessObservationUnproven) {
		t.Fatalf("unproven observation wrongly refused: %#v", got)
	}
}
