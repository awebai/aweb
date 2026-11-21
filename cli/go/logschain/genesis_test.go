package logschain

import "testing"

// A malformed genesis anchors no epoch, including before any events arrive.
func TestChainRefusesFirstEpochWithPreviousCheckpoint(t *testing.T) {
	for _, c := range loadVector(t).ChainCases {
		if c.Name != "intact_chain_of_three_producers" {
			continue
		}
		genesis := c.Genesis.genesis()
		if _, err := VerifyChain(genesis, nil, nil, nil, nil, nil); err != nil {
			t.Fatalf("valid empty epoch refused: %v", err)
		}
		genesis.PreviousCheckpointSHA256 = "00"
		if _, err := VerifyChain(genesis, nil, nil, nil, nil, nil); err == nil {
			t.Fatal("a first epoch naming a previous checkpoint verified")
		}
		return
	}
	t.Fatal("intact chain fixture missing")
}
