package wake

import (
	"context"
	"testing"

	"github.com/awebai/aw/wake/session"
)

func TestBrokerStatusReportsItsOwnBuild(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{}), Version: "1.36.5", Commit: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	resp := broker.Handle(context.Background(), ControlRequest{Op: OpStatus})
	if resp.Status == nil {
		t.Fatal("no status in control response")
	}
	if resp.Status.DaemonVersion != "1.36.5" || resp.Status.DaemonCommit != "abc123" {
		t.Fatalf("daemon reported version=%q commit=%q", resp.Status.DaemonVersion, resp.Status.DaemonCommit)
	}
}

func TestClassifyDaemonVersionNeverInventsAVersion(t *testing.T) {
	cases := []struct {
		name   string
		status Status
		want   string
	}{
		{"not running", Status{}, DaemonVersionNotRunning},
		{"old daemon omits version", Status{DaemonRunning: true, DaemonPID: 7}, DaemonVersionUnknown},
		{"daemon reports version", Status{DaemonRunning: true, DaemonVersion: "1.36.1"}, DaemonVersionReported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.status
			before := s.DaemonVersion
			s.ClassifyDaemonVersion()
			if s.DaemonVersionState != tc.want {
				t.Fatalf("state=%q want %q", s.DaemonVersionState, tc.want)
			}
			if s.DaemonVersion != before {
				t.Fatalf("classification changed the version: %q -> %q", before, s.DaemonVersion)
			}
		})
	}
}
