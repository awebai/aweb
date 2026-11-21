package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// An OATS retire and respawn under the same alias gives the alias a new key.
// A bare-alias send, as an OATS agent sends it with no flags, signs the
// recipient the team's agent list names for the alias; after the respawn
// that is the new member, so the server accepts the send and the new member
// receives it. The send before the retirement reached the old member.
func TestOATSRealBareAliasSendReachesAMemberRespawnedWithANewKey(t *testing.T) {
	world := newRealCommandWorld(t)
	root := world.addLocalMember(t, "root")
	sender := world.addLocalMember(t, "sender")
	t.Setenv("HOME", world.UserHome)
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	type spawned struct {
		identityStatusOutput
		Home string
	}
	spawn := func(dir string) spawned {
		t.Helper()
		home := filepath.Join(t.TempDir(), dir)
		world.requireCommand(t, home, "init", "--join-from", root.Home, "--join-team", world.TeamID, "--name", "worker", "--do-not-touch-agents-md")
		var status identityStatusOutput
		out := world.requireCommand(t, home, "id", "status", "--team", world.TeamID)
		if err := json.Unmarshal([]byte(out), &status); err != nil {
			t.Fatalf("status: %v\n%s", err, out)
		}
		if !status.MintComplete || status.Alias != "worker" {
			t.Fatalf("spawn incomplete: %s", out)
		}
		return spawned{identityStatusOutput: status, Home: home}
	}

	first := spawn("first")
	world.requireCommand(t, sender.Home, "mail", "send", "--to", "worker", "--subject", "before-respawn", "--body", "to the first worker")
	world.requireCommand(t, sender.Home, "chat", "send-and-leave", "worker", "chat to the first worker")
	if inbox := world.requireCommand(t, first.Home, "mail", "inbox"); !strings.Contains(inbox, "before-respawn") {
		t.Fatalf("the first worker did not receive mail: %s", inbox)
	}

	out := world.requireCommand(t, first.Home, "workspace", "delete", first.WorkspaceID)
	var retired workspaceDeleteOutput
	if err := json.Unmarshal([]byte(out), &retired); err != nil || !retired.AliasReleased {
		t.Fatalf("retirement did not release the alias: %v\n%s", err, out)
	}

	second := spawn("second")
	if second.DID == first.DID {
		t.Fatalf("the respawn reused the retired key %s", first.DID)
	}
	world.requireCommand(t, sender.Home, "mail", "send", "--to", "worker", "--subject", "after-respawn", "--body", "to the second worker")
	world.requireCommand(t, sender.Home, "chat", "send-and-leave", "worker", "chat to the second worker")
	if inbox := world.requireCommand(t, second.Home, "mail", "inbox"); !strings.Contains(inbox, "after-respawn") || strings.Contains(inbox, "before-respawn") {
		t.Fatalf("the second worker's inbox: %s", inbox)
	}
	if pending := world.requireCommand(t, second.Home, "chat", "pending"); !strings.Contains(pending, "chat to the second worker") {
		t.Fatalf("the second worker did not receive chat: %s", pending)
	}
}
