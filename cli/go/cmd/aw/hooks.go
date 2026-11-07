package main

import (
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/awebai/aw/internal/appmanifest"
)

// hookBinding is one row of the team server's hook bindings, as
// GET /v1/apps/hook-bindings returns it.
type hookBinding struct {
	BindingID      string   `json:"binding_id"`
	Kind           string   `json:"kind"`
	TeamID         string   `json:"team_id"`
	InstallationID string   `json:"installation_id"`
	Generation     int64    `json:"generation"`
	AppID          string   `json:"app_id"`
	Origin         string   `json:"origin"`
	Digest         string   `json:"digest"`
	CatalogID      string   `json:"catalog_id"`
	CatalogVersion int64    `json:"catalog_version"`
	Hook           string   `json:"hook"`
	Tool           string   `json:"tool"`
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	Scopes         []string `json:"scopes"`
	Reads          []string `json:"reads"`
	State          string   `json:"state"`
	EndedBy        string   `json:"ended_by,omitempty"`
	ActivatedAt    string   `json:"activated_at,omitempty"`
	ActiveFrom     string   `json:"active_from,omitempty"`
	RevokedAt      string   `json:"revoked_at,omitempty"`
}

// hookBindingSubject is the aweb.owner-act/1 subject for binding, built from
// the app's digest-pinned manifest. The server's row supplies only what the
// manifest cannot: the binding and installation identity. Every declared fact
// is taken from the manifest and must equal the row, so the owner signs what
// the app declared and never a row that disagrees with it. Scopes and reads
// are sorted by code point and distinct, as the contract requires.
func hookBindingSubject(binding hookBinding, resolved *appmanifest.Resolved) (map[string]any, error) {
	if binding.InstallationID == "" || binding.Generation <= 0 {
		return nil, withErrorCode("installation_identity_required", fmt.Errorf("binding %s has no installation identity yet", binding.BindingID))
	}
	mismatch := func(format string, args ...any) error {
		return withErrorCode("binding_manifest_mismatch", fmt.Errorf("binding %s: "+format, append([]any{binding.BindingID}, args...)...))
	}
	if resolved.AppID != binding.AppID || resolved.Manifest.App.Origin != binding.Origin {
		return nil, mismatch("the manifest is for %s at %s", resolved.AppID, resolved.Manifest.App.Origin)
	}
	subject := map[string]any{
		"binding_id": binding.BindingID, "installation_id": binding.InstallationID, "generation": binding.Generation,
		"app_id": binding.AppID, "origin": binding.Origin, "digest": binding.Digest, "kind": binding.Kind,
		"catalog_id": binding.CatalogID, "catalog_version": binding.CatalogVersion, "hook": binding.Hook,
	}
	declares := func(id string, version int, hook string) bool {
		return id == binding.CatalogID && int64(version) == binding.CatalogVersion && hook == binding.Hook
	}
	var hooks appmanifest.ResolvedHooks
	if resolved.Hooks != nil {
		hooks = *resolved.Hooks
	}
	switch binding.Kind {
	case "registration":
		for _, reg := range hooks.Registrations {
			if !declares(reg.CatalogID, reg.CatalogVersion, reg.Hook) || reg.Tool != binding.Tool {
				continue
			}
			tool, ok := resolved.Tool(reg.Tool)
			if !ok {
				return nil, mismatch("the manifest declares no tool %s", reg.Tool)
			}
			scopes := ownerActNames(reg.Scopes)
			if tool.Method != binding.Method || tool.Path != binding.Path || !reflect.DeepEqual(scopes, ownerActNames(binding.Scopes)) {
				return nil, mismatch("the server's target or scopes differ from the manifest")
			}
			subject["tool"], subject["method"], subject["path"] = reg.Tool, tool.Method, tool.Path
			subject["scopes"] = ownerActList(scopes)
			return subject, nil
		}
	case "production":
		for _, prod := range hooks.Productions {
			if !declares(prod.CatalogID, prod.CatalogVersion, prod.Hook) {
				continue
			}
			reads := ownerActNames(prod.Reads)
			if !reflect.DeepEqual(reads, ownerActNames(binding.Reads)) {
				return nil, mismatch("the server's reads differ from the manifest")
			}
			subject["reads"] = ownerActList(reads)
			return subject, nil
		}
	}
	return nil, mismatch("the manifest declares no %s for %s/%d %s", binding.Kind, binding.CatalogID, binding.CatalogVersion, binding.Hook)
}

// ownerActNames sorts names by code point and drops repeats.
func ownerActNames(names []string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	distinct := out[:0]
	for i, name := range out {
		if i == 0 || name != out[i-1] {
			distinct = append(distinct, name)
		}
	}
	return distinct
}

func ownerActList(names []string) []any {
	out := make([]any, len(names))
	for i, name := range names {
		out[i] = name
	}
	return out
}

// ownerActAudience is the origin of the aweb server the owner's own
// configuration selects: the one verifier the act is for. Owner acts name
// only https audiences, so a server reached over http cannot verify one.
func ownerActAudience(serverURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid aweb server URL %q", serverURL)
	}
	if u.Scheme != "https" {
		return "", withErrorCode("owner_act_requires_https", fmt.Errorf("owner acts are verified only by an https aweb server; %s is %s", u.Host, u.Scheme))
	}
	return "https://" + strings.ToLower(u.Host), nil
}
