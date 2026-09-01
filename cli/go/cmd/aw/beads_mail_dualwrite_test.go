package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// installFakeBd puts a bd shim first on PATH that records its argv and stdin
// under dir and behaves per mode: "ok" prints a bead id, "fail" exits 1,
// "hang" sleeps past the dual-write timeout.
func installFakeBd(t *testing.T, dir, mode string) {
	t.Helper()
	script := `#!/bin/sh
printf '%s\n' "$@" > "` + dir + `/bd-args"
cat > "` + dir + `/bd-stdin"
case "` + mode + `" in
  ok) printf 'bd-test-%s\n' "$(wc -c < "` + dir + `/bd-stdin" | tr -d ' ')" ;;
  fail) echo "database is locked" >&2; exit 1 ;;
  hang) sleep 30 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "bd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func dualWriteFixtures(t *testing.T, enabled bool) (beadsMailAddressMap, *awconfig.Selection, *awid.SendMessageResponse) {
	t.Helper()
	root := t.TempDir()
	settings := map[string]string{}
	if enabled {
		settings["dual-write"] = "on"
	}
	sel := &awconfig.Selection{WorkspacePath: filepath.Join(root, ".aw", "workspace.yaml")}
	resp := &awid.SendMessageResponse{MessageID: "msg-dw-1", ConversationID: "conv-dw-1"}
	return beadsMailAddressMap{entries: map[string]string{}, settings: settings}, sel, resp
}

func TestBeadsMailDualWriteRecordsBead(t *testing.T) {
	shimDir := t.TempDir()
	installFakeBd(t, shimDir, "ok")
	m, sel, resp := dualWriteFixtures(t, true)

	p := 1
	ephemeral := false
	beadsMailRecordBead(sel, m, "Water levels", "the well is low", resp, "", beadsMailEnvelope{Type: "task", Priority: &p, Ephemeral: &ephemeral})

	args, err := os.ReadFile(filepath.Join(shimDir, "bd-args"))
	if err != nil {
		t.Fatalf("bd not invoked: %v", err)
	}
	for _, want := range []string{"create", "--title", "Water levels", "--type", "message", "--stdin", "--silent", "--metadata"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("bd args missing %q:\n%s", want, args)
		}
	}
	if !strings.Contains(string(args), `"aweb_message_id":"msg-dw-1"`) || !strings.Contains(string(args), `"mail_type":"task"`) || !strings.Contains(string(args), `"ephemeral":false`) {
		t.Errorf("metadata missing ids/envelope values:\n%s", args)
	}
	stdin, _ := os.ReadFile(filepath.Join(shimDir, "bd-stdin"))
	if string(stdin) != "the well is low" {
		t.Errorf("bead body %q", stdin)
	}
	if strings.Contains(string(stdin), "beads-mail") {
		t.Errorf("envelope leaked into the bead body:\n%s", stdin)
	}

	// The new bead is mapped so a later reply can thread replies-to.
	beads := loadBeadsMailBeadMap(sel)
	beadID := beads["msg-dw-1"]
	if !strings.HasPrefix(beadID, "bd-test-") {
		t.Errorf("bead map %v", beads)
	}

	// A reply to that message gets the replies-to dependency.
	reply := &awid.SendMessageResponse{MessageID: "msg-dw-2", ConversationID: "conv-dw-1"}
	beadsMailRecordBead(sel, m, "Re: Water levels", "on it", reply, "msg-dw-1", beadsMailEnvelope{})
	args, _ = os.ReadFile(filepath.Join(shimDir, "bd-args"))
	if !strings.Contains(string(args), "replies-to:"+beadID) {
		t.Errorf("reply args missing replies-to dep:\n%s", args)
	}
}

func TestBeadsMailDualWriteDisabledByDefault(t *testing.T) {
	shimDir := t.TempDir()
	installFakeBd(t, shimDir, "ok")
	m, sel, resp := dualWriteFixtures(t, false)
	beadsMailRecordBead(sel, m, "s", "b", resp, "", beadsMailEnvelope{})
	if _, err := os.Stat(filepath.Join(shimDir, "bd-args")); err == nil {
		t.Error("bd invoked with dual-write off")
	}
}

func TestBeadsMailDualWriteFailureAndHangNeverPropagate(t *testing.T) {
	for _, mode := range []string{"fail", "hang"} {
		shimDir := t.TempDir()
		installFakeBd(t, shimDir, mode)
		m, sel, resp := dualWriteFixtures(t, true)

		// Capture stderr: the record-gap note must actually be told to the
		// user, not just implied.
		origStderr := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stderr = w

		start := time.Now()
		beadsMailRecordBead(sel, m, "s", "b", resp, "", beadsMailEnvelope{})
		elapsed := time.Since(start)

		_ = w.Close()
		os.Stderr = origStderr
		captured := make([]byte, 4096)
		n, _ := r.Read(captured)
		_ = r.Close()

		if elapsed > beadsMailDualWriteTimeout+3*time.Second {
			t.Errorf("mode=%s: dual-write took %s; the timeout bound failed", mode, elapsed)
		}
		if !strings.Contains(string(captured[:n]), "recording the message bead failed") {
			t.Errorf("mode=%s: record-gap note missing from stderr: %q", mode, captured[:n])
		}
		if beads := loadBeadsMailBeadMap(sel); len(beads) != 0 {
			t.Errorf("mode=%s: failed write still mapped a bead: %v", mode, beads)
		}
	}
}

func TestBeadsMailSettingsParsing(t *testing.T) {
	dir := t.TempDir()
	writeBeadsMailMap(t, dir, "[addresses]\n\"mayor/\" = \"acme.aweb.ai/mayor\"\n\n[settings]\ndual-write = \"on\"\n")
	m, err := loadBeadsMailAddressMap(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !beadsMailDualWriteEnabled(m) {
		t.Error("dual-write setting not read")
	}
	if _, ok := m.entries["mayor/"]; !ok {
		t.Error("addresses lost when settings present")
	}

	// Absent settings: disabled, and settings-free files still parse.
	plain := t.TempDir()
	writeBeadsMailMap(t, plain, beadsMailMapFixture)
	m, err = loadBeadsMailAddressMap(plain)
	if err != nil || beadsMailDualWriteEnabled(m) {
		t.Errorf("plain map: err=%v enabled=%v", err, beadsMailDualWriteEnabled(m))
	}
}

func TestBeadsMailBeadMapRoundTrip(t *testing.T) {
	sel := &awconfig.Selection{}
	tmp := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	saveBeadsMailBeadMap(sel, map[string]string{"m1": "bd-1"})
	if got := loadBeadsMailBeadMap(sel); got["m1"] != "bd-1" {
		t.Errorf("round trip %v", got)
	}
	raw, _ := os.ReadFile(beadsMailBeadMapPath(sel))
	var check map[string]string
	if json.Unmarshal(raw, &check) != nil {
		t.Errorf("bead map not valid JSON: %s", raw)
	}
}
