package appmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
)

// Discovery paths on an app origin. The catalog lists immutable manifest
// variants; the legacy path serves a version 1 manifest to consumers that
// predate the catalog.
const (
	DiscoveryCatalogPath = "/.well-known/aweb-app-versions.json"
	LegacyManifestPath   = "/.well-known/aweb-app.json"
)

// Discovery error codes, shared through
// test-vectors/app-manifests/app-manifest-discovery-v1.json.
const (
	CodeCatalogUnavailable    = "catalog_unavailable"
	CodeCatalogInvalid        = "catalog_invalid"
	CodeNoSupportedVariant    = "no_supported_variant"
	CodeVariantUnavailable    = "variant_unavailable"
	CodeVariantDigestMismatch = "variant_digest_mismatch"
	CodeVariantMismatch       = "variant_mismatch"
	CodeLegacyUnavailable     = "legacy_unavailable"
)

const (
	MaxCatalogBytes   = 64 << 10
	MaxManifestBytes  = 10 << 20
	maxCatalogEntries = 8
	maxVariantURLLen  = 512
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Fetch GETs one origin-relative path without following redirects and
// returns the status and at most maxBytes of body.
type Fetch func(path string, maxBytes int64) (status int, body []byte, err error)

// Variant is the manifest a consumer selected, with its exact bytes.
type Variant struct {
	Source          string
	ManifestVersion int
	URL             string
	Digest          string
	Bytes           []byte
}

type catalogDocument struct {
	CatalogVersion int              `json:"catalog_version"`
	AppID          string           `json:"app_id"`
	Variants       []catalogVariant `json:"variants"`
}

type catalogVariant struct {
	ManifestVersion int    `json:"manifest_version"`
	URL             string `json:"url"`
	Digest          string `json:"digest"`
}

// SelectVariant discovers the manifest an origin offers this consumer. It
// reads the variant catalog and selects the highest supported version,
// verifying that variant's digest, version and app id. Only a missing
// catalog (404) permits the legacy manifest. No failure falls back to another
// variant or to the legacy path.
func SelectVariant(origin string, supported []int, fetch Fetch) (*Variant, error) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	status, body, err := fetch(DiscoveryCatalogPath, MaxCatalogBytes)
	if err != nil {
		return nil, codedf(CodeCatalogUnavailable, "fetch manifest catalog: %v", err)
	}
	if status == 404 {
		return selectLegacy(origin, fetch)
	}
	if status != 200 {
		return nil, codedf(CodeCatalogUnavailable, "manifest catalog answered HTTP %d", status)
	}
	catalog, err := parseCatalog(body)
	if err != nil {
		return nil, err
	}
	var chosen *catalogVariant
	for i := range catalog.Variants {
		v := &catalog.Variants[i]
		if supportsVersion(supported, v.ManifestVersion) && (chosen == nil || v.ManifestVersion > chosen.ManifestVersion) {
			chosen = v
		}
	}
	if chosen == nil {
		return nil, codedf(CodeNoSupportedVariant, "no manifest variant this consumer supports")
	}
	status, body, err = fetch(chosen.URL, MaxManifestBytes)
	if err != nil {
		return nil, codedf(CodeVariantUnavailable, "fetch manifest variant %s: %v", chosen.URL, err)
	}
	if status != 200 {
		return nil, codedf(CodeVariantUnavailable, "manifest variant %s answered HTTP %d", chosen.URL, status)
	}
	digest := manifestDigest(body)
	if digest != chosen.Digest {
		return nil, codedf(CodeVariantDigestMismatch, "manifest variant %s has digest %s, catalog says %s", chosen.URL, digest, chosen.Digest)
	}
	version, appID := manifestIdentity(body)
	if version != chosen.ManifestVersion || appID != catalog.AppID {
		return nil, codedf(CodeVariantMismatch, "manifest variant %s is not version %d of app %q", chosen.URL, chosen.ManifestVersion, catalog.AppID)
	}
	return &Variant{Source: "catalog", ManifestVersion: version, URL: origin + chosen.URL, Digest: digest, Bytes: body}, nil
}

func selectLegacy(origin string, fetch Fetch) (*Variant, error) {
	status, body, err := fetch(LegacyManifestPath, MaxManifestBytes)
	if err != nil {
		return nil, codedf(CodeLegacyUnavailable, "fetch legacy manifest: %v", err)
	}
	if status != 200 {
		return nil, codedf(CodeLegacyUnavailable, "legacy manifest answered HTTP %d", status)
	}
	version, _ := manifestIdentity(body)
	return &Variant{Source: "legacy", ManifestVersion: version, URL: origin + LegacyManifestPath, Digest: manifestDigest(body), Bytes: body}, nil
}

func parseCatalog(body []byte) (*catalogDocument, error) {
	if len(body) > MaxCatalogBytes {
		return nil, codedf(CodeCatalogInvalid, "manifest catalog exceeds %d bytes", MaxCatalogBytes)
	}
	var catalog catalogDocument
	if err := DecodeSingleJSONStrict(body, &catalog); err != nil {
		return nil, codedf(CodeCatalogInvalid, "decode manifest catalog: %v", err)
	}
	if err := checkObjectKeys(body, reflect.TypeOf(catalogDocument{}), "manifest catalog"); err != nil {
		return nil, codedf(CodeCatalogInvalid, "decode manifest catalog: %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err == nil {
		if err := checkArrayKeys(members["variants"], reflect.TypeOf(catalogVariant{}), "manifest catalog variants[]", nil); err != nil {
			return nil, codedf(CodeCatalogInvalid, "decode manifest catalog: %v", err)
		}
	}
	if catalog.CatalogVersion != 1 {
		return nil, codedf(CodeCatalogInvalid, "unsupported catalog_version %d", catalog.CatalogVersion)
	}
	if strings.TrimSpace(catalog.AppID) == "" {
		return nil, codedf(CodeCatalogInvalid, "manifest catalog requires app_id")
	}
	if len(catalog.Variants) == 0 || len(catalog.Variants) > maxCatalogEntries {
		return nil, codedf(CodeCatalogInvalid, "manifest catalog must list 1 to %d variants", maxCatalogEntries)
	}
	seen := map[int]bool{}
	for _, v := range catalog.Variants {
		if v.ManifestVersion < 1 || seen[v.ManifestVersion] {
			return nil, codedf(CodeCatalogInvalid, "manifest catalog variant versions must be distinct and positive")
		}
		seen[v.ManifestVersion] = true
		if !validVariantPath(v.URL) {
			return nil, codedf(CodeCatalogInvalid, "manifest catalog variant url %q must be an absolute path under the install base", v.URL)
		}
		if !digestPattern.MatchString(v.Digest) {
			return nil, codedf(CodeCatalogInvalid, "manifest catalog variant digest %q is invalid", v.Digest)
		}
	}
	return &catalog, nil
}

// validVariantPath accepts an absolute path that resolves under the install
// base: no scheme, host, query, fragment, backslash, percent-encoding or dot
// segment.
func validVariantPath(path string) bool {
	if len(path) == 0 || len(path) > maxVariantURLLen || path[0] != '/' || strings.HasPrefix(path, "//") {
		return false
	}
	if strings.ContainsAny(path, "?#\\") {
		return false
	}
	if strings.Contains(path, "%") {
		return false
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	for _, r := range path {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

func supportsVersion(supported []int, version int) bool {
	for _, v := range supported {
		if v == version {
			return true
		}
	}
	return false
}

func manifestDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// manifestIdentity reads only manifest_version and app.id, by their exact
// keys, so discovery can check a variant before the consumer validates it.
// A null reads as its zero value; any other wrong type reads as no identity.
func manifestIdentity(body []byte) (int, string) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil || members == nil {
		return 0, ""
	}
	var version int
	if raw, ok := members["manifest_version"]; ok {
		if err := json.Unmarshal(raw, &version); err != nil {
			return 0, ""
		}
	}
	raw, ok := members["app"]
	if !ok || isJSONNull(raw) {
		return version, ""
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return 0, ""
	}
	var app map[string]json.RawMessage
	if err := json.Unmarshal(raw, &app); err != nil {
		return 0, ""
	}
	var id string
	if rawID, ok := app["id"]; ok {
		if err := json.Unmarshal(rawID, &id); err != nil {
			return 0, ""
		}
	}
	return version, strings.TrimSpace(id)
}
