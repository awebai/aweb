package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/awebai/aw/internal/blueprint"
	"github.com/spf13/cobra"
)

var (
	blueprintPublishProfileID   string
	blueprintPublishProfileTags []string
	blueprintPublishProfileJSON bool
)

var blueprintPublishProfileCmd = &cobra.Command{
	Use:   "publish-profile <source>",
	Short: "Publish one local blueprint profile to the team's private Library shelf",
	Long: "Pack a profile from a local blueprint source and publish it to the team's private\n" +
		"Library shelf (create-shelf-profile). --profile is optional when the source has exactly\n" +
		"one profile and required when it has more than one. The request is signed with the\n" +
		"active team certificate (library:write).",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBlueprintPublishProfile(cmd.OutOrStdout(), args[0], blueprintPublishProfileID, blueprintPublishProfileTags, blueprintPublishProfileJSON)
	},
}

func init() {
	blueprintPublishProfileCmd.Flags().StringVar(&blueprintPublishProfileID, "profile", "", "Profile id to publish (optional when the source has exactly one)")
	blueprintPublishProfileCmd.Flags().StringSliceVar(&blueprintPublishProfileTags, "tag", nil, "Tag to attach to the shelf profile (repeatable)")
	blueprintPublishProfileCmd.Flags().BoolVar(&blueprintPublishProfileJSON, "json", false, "Print machine-readable JSON")
	blueprintCmd.AddCommand(blueprintPublishProfileCmd)
}

type createShelfProfileResponse struct {
	ProfileRef string `json:"profile_ref"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`
}

// runBlueprintPublishProfile packs one profile from a local blueprint source and
// POSTs it to the team's private shelf (create-shelf-profile) with a team-signed
// request. It builds the payload locally (Go dir walk) and posts directly - it does
// not route through the manifest verb, so it needs no object/array-body CLI support.
func runBlueprintPublishProfile(out io.Writer, source, profileID string, tags []string, jsonOut bool) error {
	pub, err := blueprint.ExtractProfilePayload(source, profileID)
	if err != nil {
		return err
	}
	origin, err := installedLibraryOrigin()
	if err != nil {
		return err
	}
	target, err := url.Parse(strings.TrimRight(origin, "/") + "/v1/profiles")
	if err != nil {
		return err
	}
	if tags == nil {
		tags = []string{}
	}
	body, err := json.Marshal(map[string]any{"files": pub.Files, "tags": tags})
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	result, err := executeSignedIDRequest("POST", target, identity, body, headers, map[string]any{}, true)
	if err != nil {
		return err
	}
	if result.Status != http.StatusOK && result.Status != http.StatusCreated {
		return fmt.Errorf("create-shelf-profile failed: HTTP %d: %s", result.Status, strings.TrimSpace(string(result.Body)))
	}
	var resp createShelfProfileResponse
	if err := json.Unmarshal(result.Body, &resp); err != nil {
		return fmt.Errorf("decode create-shelf-profile response: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	fmt.Fprintf(out, "Published %s@%s to the team shelf (%d files)\n", resp.ProfileRef, resp.Version, len(pub.Files))
	fmt.Fprintf(out, "  profile digest:   %s\n", resp.Digest)
	fmt.Fprintf(out, "  source blueprint: %s@%s\n", pub.SourceBlueprintRef, pub.SourceBlueprintVersion)
	return nil
}

// installedLibraryOrigin reads the origin of the installed Library plugin manifest -
// the host the signed create-shelf-profile POST targets.
func installedLibraryOrigin() (string, error) {
	dir, err := pluginDir()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(manifestPluginManifestPath(dir, libraryPluginName))
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("the Library plugin is not installed; run `aw plugin install <library-origin>/.well-known/aweb-app.json`")
		}
		return "", err
	}
	var manifest struct {
		App struct {
			Origin string `json:"origin"`
		} `json:"app"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", fmt.Errorf("decode installed Library manifest: %w", err)
	}
	if strings.TrimSpace(manifest.App.Origin) == "" {
		return "", fmt.Errorf("installed Library manifest has no app.origin")
	}
	return manifest.App.Origin, nil
}
