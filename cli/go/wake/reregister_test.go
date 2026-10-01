package wake

import (
	"context"
	"github.com/awebai/aw/wake/session"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdenticalActiveRegisterPreservesGenerationAndLiveness(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "terminal")
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	reg := Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner, _ := broker.instanceRunner(home)
	runner.mu.Lock()
	runner.state.FirstPresentAt = time.Now().UTC()
	runner.state.Paused = true
	before := runner.state
	generation := runner.generation
	runner.mu.Unlock()
	runner.persist()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner.start(ctx)
	defer runner.stop()
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	after := runner.state
	gotGeneration := runner.generation
	runner.mu.Unlock()
	if gotGeneration != generation || !after.FirstPresentAt.Equal(before.FirstPresentAt) || !after.Paused {
		t.Fatalf("identical register reset running lifecycle: generation %d->%d state=%#v", generation, gotGeneration, after)
	}
	persisted, err := store.LoadInstance(home)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.FirstPresentAt.Equal(before.FirstPresentAt) || !persisted.Paused {
		t.Fatalf("identical register reset durable lifecycle: %#v", persisted)
	}
}

func TestChangedRegistrationReactivatesInactiveRunner(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "terminal")
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	reg := Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner, _ := broker.instanceRunner(home)
	runner.mu.Lock()
	runner.state.Inactive = true
	runner.state.LastState = "stopped"
	runner.state.Paused = true
	generation := runner.generation
	runner.mu.Unlock()
	runner.persist()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Hold the update pending until Register returns, reproducing the race.
	runner.mu.Lock()
	runner.cancel = func() {}
	runner.mu.Unlock()
	reg.IdentityHome = filepath.Join(tempHome(t, "new-identity"), ".aw")
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.cancel = nil
	runner.mu.Unlock()
	runner.start(ctx)
	defer runner.stop()
	waitForCond(t, "changed inactive registration reactivated", func() bool {
		runner.mu.Lock()
		defer runner.mu.Unlock()
		return !runner.state.Inactive && runner.generation > generation && runner.reg.IdentityHome == reg.IdentityHome
	})
	runner.mu.Lock()
	paused := runner.state.Paused
	runner.mu.Unlock()
	if !paused {
		t.Fatal("binding update lost pause")
	}
}

func TestQuietHomeUsesConfiguredOATSAndPersistsStartupLiveness(t *testing.T) {
	for _, viaEnv := range []bool{false, true} {
		name := "flag"
		if viaEnv {
			name = "environment"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			store, _ := NewStore(filepath.Join(root, "state"))
			oats := writeFakeOATS(t, root, filepath.Join(root, "unexpected-input"))
			custom := filepath.Join(root, "custom-oats")
			if err := os.Rename(oats, custom); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(oats, []byte("#!/bin/sh\nprintf '{\"ok\":false,\"error\":{\"message\":\"wrong default OATS\"}}\\n'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			oats = custom
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			server := mailServer(t, "no event offered")
			grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read"})
			client := &session.ExecClient{Bin: oats}
			if viaEnv {
				client.Bin = ""
				t.Setenv(session.OatsBinEnv, oats)
			} else {
				t.Setenv(session.OatsBinEnv, filepath.Join(root, "wrong-oats"))
			}
			broker, cancel := liveBroker(t, Config{Store: store, Session: client, ChannelCore: NewChannelCoreRunner(store)})
			defer cancel()
			if err := broker.Register(Registration{Home: root, IdentityHome: grantHome, Delivery: DeliverySession}); err != nil {
				t.Fatal(err)
			}
			waitForCond(t, "quiet home startup liveness persisted", func() bool {
				state, err := store.LoadInstance(root)
				return err == nil && !state.FirstPresentAt.IsZero() && state.LastState == "idle"
			})
			if _, err := os.Stat(filepath.Join(root, "unexpected-input")); !os.IsNotExist(err) {
				t.Fatal("startup probe typed input")
			}
		})
	}
}

func TestFreshRegistrationDiscardsOrphanedLifecycle(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "terminal")
	if err := store.SaveInstance(InstanceState{Home: home, FirstPresentAt: time.Now(), LastState: "stopped", LastError: "stale"}); err != nil {
		t.Fatal(err)
	}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Register(Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadInstance(home)
	if err != nil {
		t.Fatal(err)
	}
	if !state.FirstPresentAt.IsZero() || state.LastState != "" || state.LastError != "" {
		t.Fatalf("fresh registration inherited stale lifecycle: %#v", state)
	}
	runner, _ := broker.instanceRunner(home)
	if runner.snapshot().Phase != PhasePending {
		t.Fatal("fresh registration inherited live phase")
	}
}

func TestQuietStartupDistinguishesPresentStoppedFromNeverLaunched(t *testing.T) {
	for _, state := range []string{"stopped", "not-launched"} {
		t.Run(state, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			store, _ := NewStore(filepath.Join(root, "state"))
			oats := writeStateOATS(t, root, filepath.Join(root, "unexpected-input"), state)
			if state == "not-launched" {
				script, err := os.ReadFile(oats)
				if err != nil {
					t.Fatal(err)
				}
				script = []byte(strings.ReplaceAll(string(script), `"present":true`, `"present":false`))
				if err := os.WriteFile(oats, script, 0700); err != nil {
					t.Fatal(err)
				}
			}
			server := mailServer(t, "no event offered")
			grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read"})
			broker, cancel := liveBroker(t, Config{Store: store, Session: &session.ExecClient{Bin: oats}, ChannelCore: NewChannelCoreRunner(store)})
			defer cancel()
			if err := broker.Register(Registration{Home: root, IdentityHome: grantHome, Delivery: DeliverySession}); err != nil {
				t.Fatal(err)
			}
			waitForInstance(t, broker, root, func(inst InstanceStatus) bool {
				if state == "not-launched" {
					return inst.Phase == PhasePending && inst.ChannelCore.Running && inst.LastState == state
				}
				return inst.Phase == PhaseInactive && !inst.ChannelCore.Running && inst.LastState == state
			})
			if _, err := os.Stat(filepath.Join(root, "unexpected-input")); !os.IsNotExist(err) {
				t.Fatal("dead startup typed input")
			}
		})
	}
}
