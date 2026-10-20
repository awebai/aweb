package logschain

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/awebai/aw/strictjson"
)

const vectorPath = "../../../docs/vectors/logs-chain-v1.json"

type vectorGenesis struct {
	TeamID                   string `json:"team_id"`
	ChainEpoch               int64  `json:"chain_epoch"`
	LogsOrigin               string `json:"logs_origin"`
	CreatedAt                string `json:"created_at"`
	PreviousCheckpointSHA256 string `json:"previous_checkpoint_sha256"`
}

func (g vectorGenesis) genesis() Genesis {
	return Genesis{
		TeamID: g.TeamID, ChainEpoch: g.ChainEpoch, LogsOrigin: g.LogsOrigin,
		CreatedAt: g.CreatedAt, PreviousCheckpointSHA256: g.PreviousCheckpointSHA256,
	}
}

type vectorArtefact struct {
	Name         string         `json:"name"`
	Artefact     string         `json:"artefact"`
	Fields       map[string]any `json:"fields"`
	Error        string         `json:"error"`
	SigningBytes string         `json:"signing_bytes_b64url"`
	Signature    string         `json:"signature"`
}

type vectorEvent struct {
	Link struct {
		ChainEpoch        int64  `json:"chain_epoch"`
		TeamID            string `json:"team_id"`
		TeamSeq           int64  `json:"team_seq"`
		PrevEventHash     string `json:"prev_event_hash"`
		ReceivedAt        string `json:"received_at"`
		Hook              string `json:"hook"`
		ProducerOrigin    string `json:"producer_origin"`
		ContentCommitment string `json:"content_commitment"`
	} `json:"link"`
	EventHash string `json:"event_hash"`
	Content   *struct {
		Salt           string `json:"salt_b64url"`
		SigningBytes   string `json:"signing_bytes_b64url"`
		Signature      string `json:"signature"`
		ProducerDIDKey string `json:"producer_did_key"`
	} `json:"content"`
	PurgeAct string `json:"purge_act"`
}

type vector struct {
	GenesisCases []struct {
		Genesis     vectorGenesis `json:"genesis"`
		GenesisHash string        `json:"genesis_hash"`
	} `json:"genesis_cases"`
	CommitmentCases []struct {
		Salt              string `json:"salt_b64url"`
		SigningBytes      string `json:"signing_bytes_b64url"`
		Signature         string `json:"signature"`
		ContentCommitment string `json:"content_commitment"`
	} `json:"commitment_cases"`
	ArtefactCases struct {
		Positive []vectorArtefact `json:"positive"`
		Negative []vectorArtefact `json:"negative"`
	} `json:"artefact_cases"`
	ChainCases []struct {
		Name           string           `json:"name"`
		Genesis        vectorGenesis    `json:"genesis"`
		GenesisHash    string           `json:"genesis_hash"`
		ReceiptKeys    []string         `json:"receipt_keys"`
		CheckpointKeys []string         `json:"checkpoint_keys"`
		Events         []vectorEvent    `json:"events"`
		Receipts       []vectorArtefact `json:"receipts"`
		Checkpoints    []vectorArtefact `json:"checkpoints"`
		Report         any              `json:"report"`
	} `json:"chain_cases"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.ChainCases) == 0 || len(v.ArtefactCases.Negative) == 0 {
		t.Fatal("the logs-chain vector has no cases")
	}
	return v
}

func unb64(t *testing.T, text string) []byte {
	t.Helper()
	data, err := strictjson.DecodeBase64URL(text, "vector bytes")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func artefacts(t *testing.T, cases []vectorArtefact) []Artefact {
	out := make([]Artefact, len(cases))
	for i, c := range cases {
		out[i] = Artefact{SigningBytes: unb64(t, c.SigningBytes), Signature: c.Signature}
	}
	return out
}

func keySet(keys []string) map[string]bool {
	set := map[string]bool{}
	for _, key := range keys {
		set[key] = true
	}
	return set
}

// asJSON round-trips a value through encoding/json, so a report and the
// vector's expected report compare as the same JSON.
func asJSON(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGenesisHashesFromTheVector(t *testing.T) {
	for _, c := range loadVector(t).GenesisCases {
		hash, err := c.Genesis.genesis().Hash()
		if err != nil || hash != c.GenesisHash {
			t.Fatalf("genesis %+v: got %s, %v; want %s", c.Genesis, hash, err, c.GenesisHash)
		}
	}
}

func TestCommitmentsFromTheVector(t *testing.T) {
	for i, c := range loadVector(t).CommitmentCases {
		commitment, err := ContentCommitment(unb64(t, c.Salt), unb64(t, c.SigningBytes), c.Signature)
		if err != nil || commitment != c.ContentCommitment {
			t.Fatalf("commitment %d: got %s, %v; want %s", i, commitment, err, c.ContentCommitment)
		}
	}
}

func openArtefact(kind string, signing []byte, signature string) (map[string]any, error) {
	if kind == "receipt" {
		receipt, err := OpenReceipt(signing, signature)
		if err != nil {
			return nil, err
		}
		return receipt.Fields(), nil
	}
	checkpoint, err := OpenCheckpoint(signing, signature)
	if err != nil {
		return nil, err
	}
	return checkpoint.Fields(), nil
}

func TestArtefactsOpenFromTheVector(t *testing.T) {
	for _, c := range loadVector(t).ArtefactCases.Positive {
		fields, err := openArtefact(c.Artefact, unb64(t, c.SigningBytes), c.Signature)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if !reflect.DeepEqual(asJSON(t, fields), asJSON(t, c.Fields)) {
			t.Fatalf("%s: fields %v, want %v", c.Name, fields, c.Fields)
		}
	}
}

func TestArtefactsRefusedFromTheVector(t *testing.T) {
	for _, c := range loadVector(t).ArtefactCases.Negative {
		_, err := openArtefact(c.Artefact, unb64(t, c.SigningBytes), c.Signature)
		if code := strictjson.Code(err); code != c.Error {
			t.Fatalf("%s: refusal %q (%v), want %q", c.Name, code, err, c.Error)
		}
	}
}

func TestChainCasesFromTheVector(t *testing.T) {
	for _, c := range loadVector(t).ChainCases {
		genesis := c.Genesis.genesis()
		if hash, err := genesis.Hash(); err != nil || hash != c.GenesisHash {
			t.Fatalf("%s: genesis %s, %v; want %s", c.Name, hash, err, c.GenesisHash)
		}
		events := make([]StoredEvent, len(c.Events))
		for i, e := range c.Events {
			events[i] = StoredEvent{
				Link: Link{
					ChainEpoch: e.Link.ChainEpoch, TeamID: e.Link.TeamID, TeamSeq: e.Link.TeamSeq,
					PrevEventHash: e.Link.PrevEventHash, ReceivedAt: e.Link.ReceivedAt, Hook: e.Link.Hook,
					ProducerOrigin: e.Link.ProducerOrigin, ContentCommitment: e.Link.ContentCommitment,
				},
				EventHash: e.EventHash,
				PurgeAct:  e.PurgeAct,
			}
			if e.Content != nil {
				events[i].Content = &Content{
					Salt: unb64(t, e.Content.Salt), SigningBytes: unb64(t, e.Content.SigningBytes),
					Signature: e.Content.Signature, ProducerDIDKey: e.Content.ProducerDIDKey,
				}
			}
		}
		report, err := VerifyChain(genesis, events, keySet(c.ReceiptKeys), keySet(c.CheckpointKeys),
			artefacts(t, c.Receipts), artefacts(t, c.Checkpoints))
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if got, want := asJSON(t, report.JSON()), asJSON(t, c.Report); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: report %v, want %v", c.Name, got, want)
		}
	}
}
