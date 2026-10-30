package awid

import (
	"bytes"
	"encoding/json"
)

// ReceivedIDChain preserves integer tokens from the untrusted message carrier.
// Shape, signatures and sender binding remain the shared verifier's job.
type ReceivedIDChain map[string]any

func (chain *ReceivedIDChain) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode((*map[string]any)(chain))
}
