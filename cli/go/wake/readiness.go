package wake

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/awebai/aw/internal/releaseversion"
	"github.com/awebai/aw/wake/session"
)

type ReadinessCode string

type readinessInspectionStage string

const (
	readinessInspectStart readinessInspectionStage = "inspect_start"
	readinessInspectError readinessInspectionStage = "inspect_error"
)

const (
	Ready                         ReadinessCode = "ready"
	ReadinessDaemonUnavailable    ReadinessCode = "daemon_unavailable"
	ReadinessDaemonNotRunning     ReadinessCode = "daemon_not_running"
	ReadinessVersionUnknown       ReadinessCode = "daemon_version_unknown"
	ReadinessDaemonOutdated       ReadinessCode = "daemon_outdated"
	ReadinessHomeNotRegistered    ReadinessCode = "home_not_registered"
	ReadinessRegistrationMismatch ReadinessCode = "registration_mismatch"
	ReadinessForeignGrant         ReadinessCode = "foreign_grant_home"
	ReadinessStreamDisconnected   ReadinessCode = "stream_not_connected"
	ReadinessWorkerNotRunning     ReadinessCode = "worker_not_running"
	ReadinessWorkerError          ReadinessCode = "worker_error"
	ReadinessPaused               ReadinessCode = "paused"
	ReadinessBindingError         ReadinessCode = "binding_error"
	ReadinessInspectionError      ReadinessCode = "inspection_failed"
	ReadinessEndpointUnusable     ReadinessCode = "endpoint_unusable"
	ReadinessSessionWaiting       ReadinessCode = "session_waiting"
	ReadinessTimestampUnknown     ReadinessCode = "status_timestamp_unknown"
	ReadinessObservationInvalid   ReadinessCode = "observation_invalid"
)

type ReadinessAdvisoryCode string

const (
	ReadinessObservationAged     ReadinessAdvisoryCode = "observation_aged"
	ReadinessObservationUnproven ReadinessAdvisoryCode = "observation_unproven"
	ReadinessInspectionPending   ReadinessAdvisoryCode = "inspection_pending"
)

type ReadinessVerdict struct {
	Home          string                  `json:"home"`
	Ready         bool                    `json:"ready"`
	Code          ReadinessCode           `json:"code"`
	Reason        string                  `json:"reason"`
	Detail        string                  `json:"detail,omitempty"`
	DaemonVersion string                  `json:"daemon_version"`
	UpdatedAt     time.Time               `json:"updated_at"`
	LastInspectAt time.Time               `json:"last_inspect_at"`
	Advisories    []ReadinessAdvisoryCode `json:"advisories"`
}

type ReadinessInput struct {
	Home                 string
	Status               Status
	Registration         *Registration
	MinimumDaemonVersion string
	ControlError         error
	ForeignGrantHome     string
	Now                  time.Time
}

// EvaluateReadiness projects the existing delivery evidence, without inspecting
// or changing a session (docs/terminal-wake-broker.md:173-204,385-392). Unknown
// terminal readiness and old observations remain advisory; neither disables an
// idle receiver. Control transport failure is not proof of daemon absence.
func EvaluateReadiness(input ReadinessInput) ReadinessVerdict {
	out := ReadinessVerdict{Home: input.Home, DaemonVersion: input.Status.DaemonVersion, UpdatedAt: input.Status.UpdatedAt, Advisories: []ReadinessAdvisoryCode{}}
	fail := func(code ReadinessCode, reason string) ReadinessVerdict {
		out.Code, out.Reason = code, reason
		return out
	}
	// A missing listener establishes absence only if the store's lock probe
	// also found no owner. An interrupted exchange is still unavailable.
	if input.ControlError != nil && (!errors.Is(input.ControlError, ErrDaemonDown) || input.Status.DaemonRunning) {
		return fail(ReadinessDaemonUnavailable, "Wake control is unavailable; inspect the control error and restore the wake service before retrying.")
	}
	if !input.Status.DaemonRunning {
		return fail(ReadinessDaemonNotRunning, "Start the wake service, then rerun aw wake status.")
	}
	if input.Status.DaemonVersion == "" {
		return fail(ReadinessVersionUnknown, "Restart the wake service with a supported aw version so it can report its version.")
	}
	if input.MinimumDaemonVersion != "" {
		order, valid := releaseversion.Compare(input.Status.DaemonVersion, input.MinimumDaemonVersion)
		if !valid {
			return fail(ReadinessVersionUnknown, "The daemon or required version is not a supported release spelling; check the versions before retrying.")
		}
		if order < 0 {
			return fail(ReadinessDaemonOutdated, "Upgrade and restart the wake service to the required version, then retry.")
		}
	}
	var row *InstanceStatus
	for index := range input.Status.Instances {
		candidate := &input.Status.Instances[index]
		if candidate.Home == input.Home {
			if row != nil {
				return fail(ReadinessRegistrationMismatch, "Multiple live rows name this home; register its current binding again and retry.")
			}
			row = candidate
		}
	}
	if input.Registration == nil || row == nil {
		return fail(ReadinessHomeNotRegistered, "Register this home with aw wake register, then retry.")
	}
	out.LastInspectAt = row.LastInspectAt
	if input.ForeignGrantHome != "" {
		return fail(ReadinessForeignGrant, "A receive binding names another grant home; register only this seat's current grant home and retry.")
	}
	if row.RegistrationPending || row.ConflictHome != "" {
		return fail(ReadinessRegistrationMismatch, "The live receiver has not accepted this registration; resolve its conflict or register the current binding again.")
	}
	if err := compareReadinessRegistration(*input.Registration, *row); err != nil {
		out.Detail = err.Error()
		return fail(ReadinessRegistrationMismatch, "The live receiver differs from its saved registration; register its current binding again and retry.")
	}
	if input.Status.UpdatedAt.IsZero() {
		return fail(ReadinessTimestampUnknown, "Wake status has no observation timestamp; restart the wake service and retry.")
	}
	if input.Status.UpdatedAt.After(input.Now) || row.LastInspectAt.After(input.Now) || row.LastInspectAt.After(input.Status.UpdatedAt) {
		return fail(ReadinessObservationInvalid, "The wake observation time is in the future or after its snapshot; check the host clock and retry.")
	}
	if row.Paused || row.ChannelCore.Paused || row.ChannelCore.ReadinessPaused {
		return fail(ReadinessPaused, "Resume this home with aw wake resume before expecting delivery.")
	}
	if !row.ChannelCore.Running {
		return fail(ReadinessWorkerNotRunning, "The delivery worker is not running; inspect its status and restore the wake service.")
	}
	if row.LastError != "" || row.ChannelCore.LastError != "" {
		return fail(ReadinessWorkerError, "The wake worker reports an error; repair the error shown in its status and retry.")
	}
	if len(row.ChannelCore.BindingErrors) != 0 {
		return fail(ReadinessBindingError, "A receive binding reports an error; repair that binding and register it again.")
	}
	if row.ChannelCore.ReadinessError != "" || row.ChannelCore.ReadinessWaiting == string(readinessInspectError) {
		return fail(ReadinessInspectionError, "Session inspection failed; repair the reported inspection error and retry.")
	}
	for _, state := range []string{row.ChannelCore.ReadinessState, row.LastState} {
		switch session.NormalizeState(state) {
		case session.StateStopped, session.StateShell:
			return fail(ReadinessEndpointUnusable, "Launch the intended agent session; wake input cannot be sent to a stopped harness or shell.")
		case session.StateBlocked:
			return fail(ReadinessSessionWaiting, "The session is waiting on a person or modal; resolve it before expecting wake input.")
		}
	}
	if row.Phase == PhaseInactive {
		return fail(ReadinessEndpointUnusable, "Launch the agent session and register its current home before expecting delivery.")
	}
	for _, binding := range row.ReceiveIdentities {
		if !binding.StreamAdmitted || binding.StreamPhase != string(StreamLive) {
			return fail(ReadinessStreamDisconnected, "A registered receive stream is not connected; inspect its cause and restore the connection.")
		}
	}
	if input.Now.Sub(input.Status.UpdatedAt) > 30*time.Second || (!row.LastInspectAt.IsZero() && input.Now.Sub(row.LastInspectAt) > 30*time.Second) {
		out.Advisories = append(out.Advisories, ReadinessObservationAged)
	}
	if row.LastInspectAt.IsZero() || row.ChannelCore.ReadinessState == "" || row.ChannelCore.ReadinessWaiting == "" {
		out.Advisories = append(out.Advisories, ReadinessObservationUnproven)
	}
	if row.ChannelCore.ReadinessWaiting == string(readinessInspectStart) {
		out.Advisories = append(out.Advisories, ReadinessInspectionPending)
	}
	out.Ready, out.Code, out.Reason = true, Ready, "The registered receiver is ready; this is not a delivery or consumption receipt."
	return out
}

// The saved registration and the live row must describe the same complete
// receiver. Normalization stays with Registration, the mint/dispatch owner.
func compareReadinessRegistration(expected Registration, row InstanceStatus) error {
	live := Registration{Home: row.Home, IdentityHome: row.IdentityHome, Delivery: row.Delivery, RuntimeDelivery: row.RuntimeDelivery, PrimaryIdentityHome: row.PrimaryIdentityHome, Backend: row.Backend, PresenceIdentities: row.PresenceIdentities}
	for _, binding := range row.ReceiveIdentities {
		if binding.DeliveryOwner != ReceiveOwnerSessionHints {
			return fmt.Errorf("receive owner differs")
		}
		live.ReceiveIdentities = append(live.ReceiveIdentities, ReceiveIdentity{IdentityHome: binding.IdentityHome, TeamID: binding.TeamID, Label: binding.Label, DeliveryOwner: binding.DeliveryOwner, EventClasses: binding.EventClasses, Controls: binding.Controls})
	}
	canonicalExpected, err := expected.Normalized()
	if err != nil {
		return err
	}
	canonicalLive, err := live.Normalized()
	if err != nil {
		return err
	}
	canonicalExpected.RegisteredAt, canonicalLive.RegisteredAt = time.Time{}, time.Time{}
	for _, registration := range []*Registration{&canonicalExpected, &canonicalLive} {
		slices.SortFunc(registration.ReceiveIdentities, func(left, right ReceiveIdentity) int {
			return strings.Compare(left.IdentityHome+"\x00"+left.TeamID, right.IdentityHome+"\x00"+right.TeamID)
		})
	}
	if !reflect.DeepEqual(canonicalExpected, canonicalLive) {
		return fmt.Errorf("registration differs")
	}
	return nil
}
