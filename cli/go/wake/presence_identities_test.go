package wake

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/awebai/aw/wake/session"
)

func presenceRegistration(t *testing.T) Registration {
	t.Helper()
	home := tempHome(t, "session")
	primary := filepath.Join(tempHome(t, "primary"), ".aw")
	poll := filepath.Join(tempHome(t, "poll"), ".aw")
	writeWakeTestTeamState(t, poll, "team:poll")
	return Registration{Home: home, RuntimeDelivery: RuntimeDeliveryNativePi,
		PrimaryIdentityHome: primary, PresenceIdentities: []PresenceIdentity{{IdentityHome: poll}}}
}

func TestPresenceIdentitiesValidateNativeWithoutReceive(t *testing.T) {
	for _, runtime := range []string{RuntimeDeliveryNativePi, RuntimeDeliveryNativeChannel} {
		t.Run(runtime, func(t *testing.T) {
			reg := presenceRegistration(t)
			reg.RuntimeDelivery = runtime
			normalized, err := reg.Normalized()
			if err != nil {
				t.Fatal(err)
			}
			if len(normalized.ReceiveBindings()) != 0 {
				t.Fatalf("presence became receive bindings: %+v", normalized.ReceiveBindings())
			}
			if got := normalized.PresenceIdentities[0].TeamID; got != "team:poll" {
				t.Fatalf("effective team=%q", got)
			}
			child := &ChannelCoreChild{reg: normalized}
			if len(child.initLine().Bindings) != 0 {
				t.Fatal("presence entered child config")
			}
			encoded, err := json.Marshal(child.initLine())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), normalized.PresenceIdentities[0].IdentityHome) {
				t.Fatal("presence home leaked into child config")
			}
			clone := normalized.clone()
			clone.PresenceIdentities[0].TeamID = "changed"
			if normalized.PresenceIdentities[0].TeamID != "team:poll" {
				t.Fatal("presence snapshot shares mutable backing slice")
			}
		})
	}
}

func TestPresenceIdentitiesValidationRefusals(t *testing.T) {
	for _, name := range []string{"empty", "relative", "missing", "file", "noncanonical", "unreadable", "no-team", "primary", "receive-other-team", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			reg := presenceRegistration(t)
			primary := reg.PrimaryIdentityHome
			reg.RuntimeDelivery = RuntimeDeliveryExternalSession
			reg.ReceiveIdentities = []ReceiveIdentity{{IdentityHome: primary, TeamID: "team:receive"}}
			p := &reg.PresenceIdentities[0]
			want := "presence_identities"
			switch name {
			case "empty":
				p.IdentityHome = ""
			case "relative":
				p.IdentityHome = "relative"
			case "missing":
				p.IdentityHome = filepath.Join(p.IdentityHome, "missing")
			case "file":
				path := filepath.Join(p.IdentityHome, "not-a-directory")
				if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
				p.IdentityHome = path
			case "noncanonical":
				link := filepath.Join(reg.Home, "poll-link")
				if err := os.Symlink(p.IdentityHome, link); err != nil {
					t.Fatal(err)
				}
				p.IdentityHome = link
			case "unreadable":
				if os.Geteuid() == 0 {
					t.Skip("root can read directories without read permission")
				}
				if err := os.Chmod(p.IdentityHome, 0000); err != nil {
					t.Fatal(err)
				}
				path := p.IdentityHome
				t.Cleanup(func() { _ = os.Chmod(path, 0700) })
			case "no-team":
				if err := os.Remove(filepath.Join(p.IdentityHome, "teams.yaml")); err != nil {
					t.Fatal(err)
				}
			case "primary":
				reg.ReceiveIdentities = nil
				reg.RuntimeDelivery = RuntimeDeliveryNativePi
				p.IdentityHome = primary
				p.TeamID = "team:other"
				want = "overlaps primary_identity_home"
			case "receive-other-team":
				reg.PrimaryIdentityHome = ""
				p.IdentityHome = primary
				p.TeamID = "team:other"
				want = "overlaps receive identity_home"
			case "duplicate":
				p.TeamID = "team:poll"
				reg.PresenceIdentities = append(reg.PresenceIdentities, *p)
				want = "duplicate presence identity_home"
			}
			if err := reg.Validate(); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("validation=%v; want %s refusal", err, want)
			}
		})
	}
}

func TestPresenceIdentitiesKeepExplicitTeamsAndGrantTeam(t *testing.T) {
	reg := presenceRegistration(t)
	reg.PresenceIdentities[0].TeamID = "team:first"
	reg.PresenceIdentities = append(reg.PresenceIdentities, PresenceIdentity{IdentityHome: reg.PresenceIdentities[0].IdentityHome, TeamID: "team:second"})
	grant := filepath.Join(tempHome(t, "grant"), ".aw")
	if err := os.WriteFile(filepath.Join(grant, "grant.yaml"), []byte("team_id: team:grant\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reg.PresenceIdentities = append(reg.PresenceIdentities, PresenceIdentity{IdentityHome: grant})
	normalized, err := reg.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, p := range normalized.PresenceIdentities {
		got = append(got, p.TeamID)
	}
	if !reflect.DeepEqual(got, []string{"team:first", "team:second", "team:grant"}) {
		t.Fatalf("teams=%v", got)
	}
}

func TestPresenceIdentitiesLegacyReceiveAndStatus(t *testing.T) {
	store := tempStore(t)
	reg := presenceRegistration(t)
	reg.RuntimeDelivery = ""
	reg.Delivery = DeliverySession
	reg.IdentityHome = reg.PrimaryIdentityHome
	if err := store.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	stored, ok, err := store.LoadRegistration(reg.Home)
	if err != nil || !ok {
		t.Fatalf("load=%t %v", ok, err)
	}
	normalized, err := stored.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.ReceiveBindings()) != 1 {
		t.Fatal("legacy receive binding was lost")
	}
	if normalized.PresenceIdentities[0].TeamID != "team:poll" {
		t.Fatal("presence team was not pinned")
	}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	broker.Reconcile()
	live := broker.Status()
	fallback, err := StatusFromStore(store, DefaultMaxStreams)
	if err != nil {
		t.Fatal(err)
	}
	for name, status := range map[string]Status{"live": live, "fallback": fallback} {
		if len(status.Instances) != 1 || !reflect.DeepEqual(status.Instances[0].PresenceIdentities, normalized.PresenceIdentities) {
			t.Fatalf("%s status=%+v", name, status.Instances)
		}
	}
	// Presence-only edits apply to the live runner without changing receive ownership.
	runner, _ := broker.instanceRunner(reg.Home)
	normalized.PresenceIdentities = nil
	if runner.updateRegistration(normalized) {
		t.Fatal("presence-only edit queued a receive reconfiguration")
	}
	if len(runner.registrationSnapshot().PresenceIdentities) != 0 {
		t.Fatal("presence removal was not applied")
	}
	// A presence target never becomes stream ownership, even on the native-only path.
	native := presenceRegistration(t)
	broker2, err := NewBroker(Config{Store: tempStore(t), Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker2.Register(native); err != nil {
		t.Fatal(err)
	}
	if len(broker2.Status().Streams) != 0 {
		t.Fatal("presence identity opened a stream")
	}
}
