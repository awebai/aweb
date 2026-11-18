package releaseverify

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
)

//go:embed channels.json
var channelVersions []byte

type Channels struct {
	Pi                        string `json:"pi"`
	ClaudeChannel             string `json:"claude_channel"`
	ClaudeMarketplaceRevision string `json:"claude_marketplace_revision"`
}

func ChannelVersions() Channels {
	var versions Channels
	if err := json.Unmarshal(channelVersions, &versions); err != nil {
		panic("invalid embedded channel mapping: " + err.Error())
	}
	return versions
}

func ClaudeMarketplace() (string, error) {
	revision := ChannelVersions().ClaudeMarketplaceRevision
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(revision) {
		return "", fmt.Errorf("this aw build has no pinned Claude marketplace revision. Retry with a published aw release that includes its channel compatibility mapping.")
	}
	return "https://github.com/awebai/claude-plugins.git#" + revision, nil
}
