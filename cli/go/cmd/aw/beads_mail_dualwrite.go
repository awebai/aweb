package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Data-plane dual-write, per docs/beads-mail-delegate.md §12: with
// [settings] dual-write = "on" in .beads/aweb-mail.toml, every delivered
// send/reply is also recorded as a beads issue (type: message) so the graph
// keeps the durable record while aweb does delivery.
//
// Isolation rules (abhf.7 review scope): the delegate is exec'd BY bd and
// invokes a child bd here, so the write is bounded by a hard timeout and can
// never fail or hang the send — a failed or slow bead write reports the
// record gap and the command still exits 0. The child runs after delivery
// succeeded, never before.

const beadsMailDualWriteTimeout = 5 * time.Second

func beadsMailDualWriteEnabled(m beadsMailAddressMap) bool {
	return m.settings["dual-write"] == "on"
}

// beadsMailBeadMapPath stores aweb message id -> bead id, workspace-local,
// so replies can thread the beads graph via replies-to.
func beadsMailBeadMapPath(sel *awconfig.Selection) string {
	return filepath.Join(filepath.Dir(beadsMailStatePath(sel)), "beads.json")
}

func loadBeadsMailBeadMap(sel *awconfig.Selection) map[string]string {
	content, err := os.ReadFile(beadsMailBeadMapPath(sel))
	if err != nil {
		return map[string]string{}
	}
	beads := map[string]string{}
	if json.Unmarshal(content, &beads) != nil {
		return map[string]string{}
	}
	return beads
}

func saveBeadsMailBeadMap(sel *awconfig.Selection, beads map[string]string) {
	path := beadsMailBeadMapPath(sel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	encoded, err := json.Marshal(beads)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, encoded, 0o600)
}

// beadsMailRecordBead writes the message bead via the bd CLI after a
// successful delivery. body is the user's body WITHOUT the beads-mail
// envelope — the structured values ride bd metadata instead. replyToID is
// the aweb message id this message replies to, if any; when the local bead
// map knows that message's bead, the new bead gets a replies-to dependency
// (verified live against bd 1.1.2: --deps "replies-to:<id>" at create).
func beadsMailRecordBead(sel *awconfig.Selection, m beadsMailAddressMap, subject, body string, resp *awid.SendMessageResponse, replyToID string, env beadsMailEnvelope) {
	if !beadsMailDualWriteEnabled(m) || resp == nil {
		return
	}
	metadata := map[string]any{
		"aweb_message_id":      resp.MessageID,
		"aweb_conversation_id": resp.ConversationID,
	}
	if env.Type != "" {
		metadata["mail_type"] = env.Type
	}
	if env.Priority != nil {
		metadata["mail_priority"] = *env.Priority
	}
	if env.Pinned {
		metadata["pinned"] = true
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil {
		return
	}

	args := []string{"create", "--title", subject, "--type", "message", "--stdin", "--silent", "--metadata", string(encodedMetadata)}
	beads := loadBeadsMailBeadMap(sel)
	if replyToID != "" {
		if parentBead := beads[replyToID]; parentBead != "" {
			args = append(args, "--deps", "replies-to:"+parentBead)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), beadsMailDualWriteTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bd", args...)
	// After the deadline kills bd, don't wait on pipes an orphaned grandchild
	// may still hold open — the send must return regardless.
	cmd.WaitDelay = time.Second
	cmd.Stdin = strings.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if ctx.Err() == context.DeadlineExceeded {
			detail = fmt.Sprintf("bd did not answer within %s (the database is likely busy - concurrent writers serialize)", beadsMailDualWriteTimeout)
		} else if detail == "" {
			detail = err.Error()
		}
		fmt.Fprintf(os.Stderr, "note: delivered via aweb, but recording the message bead failed: %s. The beads graph is missing this message.\n", sanitizeBeadsMailDisplay(detail))
		return
	}
	beadID := strings.TrimSpace(stdout.String())
	if beadID == "" {
		fmt.Fprintln(os.Stderr, "note: delivered via aweb, but bd returned no bead id; the beads graph may be missing this message.")
		return
	}
	beads[resp.MessageID] = beadID
	saveBeadsMailBeadMap(sel, beads)
	fmt.Printf("recorded as %s\n", sanitizeBeadsMailDisplay(beadID))
}
