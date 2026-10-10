package awid

import (
	"os"
	"path/filepath"
	"testing"
)

// Malformed persisted checkpoints must not reopen trust or crash a reader.
func TestReceivedCheckpointMalformedFile(t *testing.T) {
	for _, value := range []string{"null", "[]", "{https://registry.test: {did:aw:sender: null}}"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_agents.yaml")
			data := "pins: {}\naddresses: {}\nreceived_identity_heads: " + value + "\n"
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			ps, err := LoadPinStore(path)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{}
			c.SetPinStore(ps, path)
			if _, err := c.receivedCheckpoint("https://registry.test", "did:aw:sender"); err == nil {
				t.Fatal("malformed persisted checkpoint accepted")
			}
		})
	}
}
