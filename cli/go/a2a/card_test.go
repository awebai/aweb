package a2a

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type vectorFile struct {
	AgentCards []vectorCard `json:"agent_cards"`
}

type vectorCard struct {
	Name                 string         `json:"name"`
	Path                 string         `json:"path"`
	CanonicalNoSignature string         `json:"canonical_no_signatures"`
	Digest               string         `json:"digest"`
	Card                 map[string]any `json:"card"`
}

func TestGeneratedCardsMatchA2AV1Fixtures(t *testing.T) {
	vector := readVector(t)
	generated := map[string]Card{
		"hosted_default":       mustRootDefaultCard(t, CardConfig{Host: "team.aweb.ai", RouteID: "r_support", Name: "Aweb Support", Description: "Hosted support agent for aweb users.", Provider: Provider{Organization: "aweb", URL: "https://aweb.ai"}, Skills: []Skill{{ID: "support", Name: "Support", Description: "Answers product and onboarding questions.", Tags: []string{"support", "onboarding"}}}}),
		"byot_default":         mustRootDefaultCard(t, CardConfig{Host: "acme.com", RouteID: "r_help", Name: "Acme Help", Description: "Customer support agent for Acme products.", Provider: Provider{Organization: "Acme", URL: "https://acme.com"}, Skills: []Skill{{ID: "order-status", Name: "Order status", Description: "Look up order status from an order ID.", Tags: []string{"support", "orders"}}}}),
		"byot_router_root":     mustRootRouterCard(t, RouterCardConfig{Host: "acme.com", Name: "Acme A2A Gateway", Description: "A2A gateway for Acme agents. Exact agent cards are published in the Acme/aweb directory.", Provider: Provider{Organization: "Acme", URL: "https://acme.com"}, Skills: []Skill{{ID: "route-to-agent", Name: "Route to Acme agents", Description: "Routes customer tasks to configured Acme agents when enough information is provided.", Tags: []string{"router"}}}}),
		"per_address_research": mustPerAddressCard(t, CardConfig{Host: "acme.com", RouteID: "r_research", Name: "Acme Research", Description: "Research agent for Acme technical investigations.", Provider: Provider{Organization: "Acme", URL: "https://acme.com"}, Streaming: true, DefaultOutputModes: []string{"text/plain", "application/json"}, Skills: []Skill{{ID: "technical-research", Name: "Technical research", Description: "Investigates technical questions and returns concise findings.", Tags: []string{"research", "technical"}}}}),
	}

	for _, fixture := range vector.AgentCards {
		t.Run(fixture.Name, func(t *testing.T) {
			card, ok := generated[fixture.Name]
			if !ok {
				t.Fatalf("missing generated card for fixture %s", fixture.Name)
			}
			gotMap, err := cardToMap(card)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotMap, fixture.Card) {
				t.Fatalf("generated card map mismatch\n got: %#v\nwant: %#v", gotMap, fixture.Card)
			}
			digest, err := CardDigest(card)
			if err != nil {
				t.Fatal(err)
			}
			if digest.CanonicalNoSignatures != fixture.CanonicalNoSignature {
				t.Fatalf("canonical mismatch\n got: %s\nwant: %s", digest.CanonicalNoSignatures, fixture.CanonicalNoSignature)
			}
			if digest.Value != fixture.Digest {
				t.Fatalf("digest: got %s, want %s", digest.Value, fixture.Digest)
			}
			if err := ValidateCard(card, ValidationOptions{CardPath: fixture.Path, RequireJSONRPCOnly: true, DisallowDirectTenant: true, RequireMediaTypeModes: true}); err != nil {
				t.Fatalf("ValidateCard: %v", err)
			}
		})
	}
}

func TestValidateCardRejectsInvalidShapes(t *testing.T) {
	vector := readVector(t)
	base := cloneMapForTest(vector.AgentCards[0].Card)

	t.Run("top_level_protocol_version", func(t *testing.T) {
		card := cloneMapForTest(base)
		card["protocolVersion"] = "1.0"
		requireValidateErrorContains(t, card, ValidationOptions{RequireJSONRPCOnly: true}, "not in pinned A2A")
	})

	t.Run("card_version_protocol_confusion", func(t *testing.T) {
		card := cloneMapForTest(base)
		card["version"] = "1.0"
		requireValidateErrorContains(t, card, ValidationOptions{RequireJSONRPCOnly: true}, "looks like protocol version")
	})

	t.Run("plain_text_mode", func(t *testing.T) {
		card := cloneMapForTest(base)
		card["defaultInputModes"] = []any{"text"}
		requireValidateErrorContains(t, card, ValidationOptions{RequireMediaTypeModes: true}, "not a media type")
	})

	t.Run("tenant_on_direct_card", func(t *testing.T) {
		card := cloneMapForTest(vector.AgentCards[3].Card)
		interfaces := card["supportedInterfaces"].([]any)
		iface := cloneMapForTest(interfaces[0].(map[string]any))
		iface["tenant"] = "r_research"
		card["supportedInterfaces"] = []any{iface}
		requireValidateErrorContains(t, card, ValidationOptions{CardPath: vector.AgentCards[3].Path, RequireJSONRPCOnly: true, DisallowDirectTenant: true}, "omit supportedInterfaces")
	})

	t.Run("unknown_schema_field", func(t *testing.T) {
		card := cloneMapForTest(base)
		card["unknown"] = true
		requireValidateErrorContains(t, card, ValidationOptions{}, "not in pinned A2A")
	})

	t.Run("missing_supported_interfaces", func(t *testing.T) {
		card := cloneMapForTest(base)
		delete(card, "supportedInterfaces")
		requireValidateErrorContains(t, card, ValidationOptions{}, "supportedInterfaces")
	})

	t.Run("unknown_capability", func(t *testing.T) {
		card := cloneMapForTest(base)
		capabilities := cloneMapForTest(card["capabilities"].(map[string]any))
		capabilities["stateTransitionHistory"] = true
		card["capabilities"] = capabilities
		requireValidateErrorContains(t, card, ValidationOptions{}, "AgentCapabilities")
	})
}

func TestVerificationResultStubs(t *testing.T) {
	card := mustRootDefaultCard(t, CardConfig{Host: "team.aweb.ai", RouteID: "r_support", Name: "Aweb Support", Description: "Hosted support agent for aweb users.", Provider: Provider{Organization: "aweb", URL: "https://aweb.ai"}, Skills: []Skill{{ID: "support", Name: "Support", Description: "Answers product and onboarding questions.", Tags: []string{"support"}}}})
	tier0, err := VerifyTier0(card)
	if err != nil {
		t.Fatal(err)
	}
	if tier0.Tier != VerificationTier0 || tier0.Status != VerificationIgnored || !strings.HasPrefix(tier0.Digest, "sha256:") {
		t.Fatalf("unexpected tier0 result: %+v", tier0)
	}
	tier2, err := VerifyTier2Unavailable(card)
	if err != nil {
		t.Fatal(err)
	}
	if tier2.Tier != VerificationTier2 || tier2.Status != VerificationAWIDRequired || tier2.Code == "" {
		t.Fatalf("unexpected tier2 unavailable result: %+v", tier2)
	}
}

func requireValidateErrorContains(t *testing.T, card map[string]any, options ValidationOptions, want string) {
	t.Helper()
	err := ValidateCardMap(card, options)
	if err == nil {
		t.Fatalf("ValidateCardMap succeeded, want error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("ValidateCardMap error %q does not contain %q", err.Error(), want)
	}
}

func mustRootDefaultCard(t *testing.T, config CardConfig) Card {
	t.Helper()
	card, err := RootDefaultCard(config)
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func mustRootRouterCard(t *testing.T, config RouterCardConfig) Card {
	t.Helper()
	card, err := RootRouterCard(config)
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func mustPerAddressCard(t *testing.T, config CardConfig) Card {
	t.Helper()
	card, err := PerAddressCard(config)
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func readVector(t *testing.T) vectorFile {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "docs", "vectors", "a2a-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector vectorFile
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func cloneMapForTest(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// Card digests are published by one aw and recomputed by another, so their
// canonical bytes write U+2028 and U+2029 as six-character escapes. This
// digest was computed at commit 8e8d008c8.
func TestCardDigestOfTextWithLineSeparatorsIsStable(t *testing.T) {
	lineSeparator, paragraphSeparator := string(rune(0x2028)), string(rune(0x2029))
	card := Card{
		Name: "agent", Description: "line" + lineSeparator + "paragraph" + paragraphSeparator + "end <&>", Version: "1",
		Capabilities: &Capabilities{}, DefaultInputModes: []string{"text/plain"}, DefaultOutputModes: []string{"text/plain"},
		SupportedInterfaces: []Interface{}, Skills: []Skill{},
	}
	digest, err := CardDigest(card)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := `{"capabilities":{},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"description":"line` +
		"\\u2028" + `paragraph` + "\\u2029" + `end <&>","name":"agent","skills":[],"supportedInterfaces":[],"version":"1"}`
	if digest.CanonicalNoSignatures != wantCanonical {
		t.Fatalf("canonical = %q, want %q", digest.CanonicalNoSignatures, wantCanonical)
	}
	if want := "sha256:774f392afd24f5dafec9f81ad2ab84047292da7f95ad1a4ed57e727ba6e9be4d"; digest.Value != want {
		t.Fatalf("digest = %s, want %s", digest.Value, want)
	}
}

// The card cases of the shared canonical JSON vector's escaped form: the bytes
// a card digest is computed over, and the digest.
func TestCardDigestReproducesTheEscapedFormVector(t *testing.T) {
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "docs", "vectors", "canonical-json-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Cases []struct {
			Name         string          `json:"name"`
			Value        json.RawMessage `json:"value"`
			CanonicalHex string          `json:"canonical_hex"`
			CardDigest   string          `json:"card_digest"`
		} `json:"escaped_line_separator_cases"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	cards := 0
	for _, c := range vector.Cases {
		if c.CardDigest == "" {
			continue
		}
		cards++
		t.Run(c.Name, func(t *testing.T) {
			var card Card
			if err := json.Unmarshal(c.Value, &card); err != nil {
				t.Fatal(err)
			}
			digest, err := CardDigest(card)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString([]byte(digest.CanonicalNoSignatures)); got != c.CanonicalHex {
				t.Fatalf("canonical bytes\n got %s\nwant %s", got, c.CanonicalHex)
			}
			if digest.Value != c.CardDigest {
				t.Fatalf("digest = %s, want %s", digest.Value, c.CardDigest)
			}
		})
	}
	if cards == 0 {
		t.Fatal("shared vector has no card digest case")
	}
}
