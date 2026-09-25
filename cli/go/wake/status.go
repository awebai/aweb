package wake

import "time"

// Status is what `aw wake status` reports and what the daemon mirrors into
// status.json so the CLI can answer while the daemon is down.
//
// It holds counts, ids, states and timestamps. It never holds message content
// (§6), and it holds no presented marks (§4).
type Status struct {
	UpdatedAt     time.Time `json:"updated_at"`
	StateDir      string    `json:"state_dir"`
	DaemonRunning bool      `json:"daemon_running"`
	DaemonPID     int       `json:"daemon_pid,omitempty"`
	// DaemonVersion and DaemonCommit are reported by the running daemon about
	// its own build. Daemons that predate these fields omit them, so a reader
	// must treat absence as unknown and never substitute its own version.
	DaemonVersion string `json:"daemon_version,omitempty"`
	DaemonCommit  string `json:"daemon_commit,omitempty"`
	// DaemonVersionState is set by the status reader (ClassifyDaemonVersion):
	// reported, unknown or not_running.
	DaemonVersionState string           `json:"daemon_version_state,omitempty"`
	MaxStreams         int              `json:"max_streams"`
	Streams            []StreamStatus   `json:"streams"`
	Instances          []InstanceStatus `json:"instances"`
}

// Daemon version states for Status.DaemonVersionState.
const (
	// DaemonVersionReported means the running daemon reported its own version.
	DaemonVersionReported = "reported"
	// DaemonVersionUnknown means a daemon is running but did not report a
	// version. Its compatibility is unproven; this is not proof that it is
	// older than the CLI.
	DaemonVersionUnknown = "unknown"
	// DaemonVersionNotRunning means no daemon is running.
	DaemonVersionNotRunning = "not_running"
)

// ClassifyDaemonVersion sets DaemonVersionState from what the daemon itself
// reported. It never fills DaemonVersion in.
func (s *Status) ClassifyDaemonVersion() {
	switch {
	case !s.DaemonRunning:
		s.DaemonVersionState = DaemonVersionNotRunning
	case s.DaemonVersion != "":
		s.DaemonVersionState = DaemonVersionReported
	default:
		s.DaemonVersionState = DaemonVersionUnknown
	}
}

// StreamStatus is one identity's event stream.
type StreamStatus struct {
	IdentityHome string    `json:"identity_home"`
	Phase        string    `json:"phase"`
	LastError    string    `json:"last_error,omitempty"`
	UnreadCount  int       `json:"unread_count,omitempty"`
	ConnectedAt  time.Time `json:"connected_at,omitempty"`
	// Admitted is false for a registration past the configured stream bound.
	// Such a registration is reported here, never silently dropped (§4).
	Admitted bool `json:"admitted"`
}

// ReceiveIdentityStatus is one broker-owned receive binding for an instance.
type ReceiveIdentityStatus struct {
	IdentityHome   string   `json:"identity_home"`
	TeamID         string   `json:"team_id,omitempty"`
	Label          string   `json:"label,omitempty"`
	DeliveryOwner  string   `json:"delivery_owner,omitempty"`
	EventClasses   []string `json:"event_classes,omitempty"`
	Controls       bool     `json:"controls,omitempty"`
	StreamAdmitted bool     `json:"stream_admitted"`
}

// InstancePhase is a registration's lifecycle position.
const (
	// PhasePending means no confirmed live inspect yet. Every pending state
	// and every error is tolerated here, and nothing is submitted.
	PhasePending = "pending"
	// PhaseActive means at least one confirmed live inspect has happened.
	PhaseActive = "active"
	// PhaseInactive means `stopped` was seen after a confirmed live
	// observation. Removal stays with the retire hook.
	PhaseInactive = "inactive"
)

// InstanceStatus is one registered instance.
type InstanceStatus struct {
	Home                string                  `json:"home"`
	IdentityHome        string                  `json:"identity_home"`
	RuntimeDelivery     string                  `json:"runtime_delivery,omitempty"`
	PrimaryIdentityHome string                  `json:"primary_identity_home,omitempty"`
	ReceiveIdentities   []ReceiveIdentityStatus `json:"receive_identities,omitempty"`
	Backend             string                  `json:"backend,omitempty"`
	Delivery            string                  `json:"delivery"`
	RegisteredAt        time.Time               `json:"registered_at"`
	Phase               string                  `json:"phase"`
	Paused              bool                    `json:"paused"`
	PendingHints        int                     `json:"pending_hints"`
	Evicted             int                     `json:"evicted_hints"`
	LastInspectAt       time.Time               `json:"last_inspect_at,omitempty"`
	LastAttemptAt       time.Time               `json:"last_attempt_at,omitempty"`
	LastSubmitAt        time.Time               `json:"last_submit_at,omitempty"`
	LastState           string                  `json:"last_state,omitempty"`
	LastError           string                  `json:"last_error,omitempty"`
	UnreadCount         int                     `json:"unread_count,omitempty"`
	StreamAdmitted      bool                    `json:"stream_admitted"`
}
