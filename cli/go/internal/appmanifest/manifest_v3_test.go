package appmanifest

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// v3Manifest is a version 3 manifest of app "logs" at https://logs.example.com
// whose owner_acts member is the given JSON, or absent when it is "".
func v3Manifest(version int, ownerActs string) []byte {
	doc := fmt.Sprintf(`{"manifest_version":%d,"app":{"id":"logs","version":"1.0.0","origin":"https://logs.example.com"},"tools":[]`, version)
	if ownerActs != "" {
		doc += `,"owner_acts":` + ownerActs
	}
	return []byte(doc + "}")
}

func v3Role(name string) string {
	return fmt.Sprintf(`{"name":%q,"label":"Log reader","acts":["human-credential.replace","human-role.designate","human-role.revoke"],"notice_contact":false}`, name)
}

func v3OwnerActs(origin string, roles ...string) string {
	return fmt.Sprintf(`{"origin":%q,"roles":[%s]}`, origin, strings.Join(roles, ","))
}

func TestManifestV3DeclaresTheOwnerActsOriginAndRoles(t *testing.T) {
	resolved, err := Load(v3Manifest(3, v3OwnerActs("https://console.logs.example.com:8443", v3Role("logs.reader"))), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if resolved.ManifestVersion != 3 {
		t.Fatalf("version %d", resolved.ManifestVersion)
	}
	if resolved.OwnerActs == nil || resolved.OwnerActs.Origin != "https://console.logs.example.com:8443" {
		t.Fatalf("owner_acts origin: %#v", resolved.OwnerActs)
	}
	if len(resolved.OwnerActs.Roles) != 1 || resolved.OwnerActs.Roles[0].Name != "logs.reader" || resolved.OwnerActs.Roles[0].Label != "Log reader" {
		t.Fatalf("owner_acts roles: %#v", resolved.OwnerActs.Roles)
	}
}

func TestManifestV3WithoutOwnerActsDeclaresNoOwnerRole(t *testing.T) {
	resolved, err := Load(v3Manifest(3, ""), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if resolved.OwnerActs != nil {
		t.Fatalf("owner_acts: %#v", resolved.OwnerActs)
	}
}

func TestManifestV3RefusesAnOwnerActsOriginOutsideTheAudienceGrammar(t *testing.T) {
	for name, origin := range map[string]string{
		"the app's host":           "https://logs.example.com",
		"the app's host on a port": "https://logs.example.com:8443",
		"a path":                   "https://console.logs.example.com/console",
		"a trailing slash":         "https://console.logs.example.com/",
		"http":                     "http://console.logs.example.com",
		"an upper-case host":       "https://Console.logs.example.com",
		"a query":                  "https://console.logs.example.com?x=1",
		"userinfo":                 "https://u@console.logs.example.com",
		"empty":                    "",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(v3Manifest(3, v3OwnerActs(origin, v3Role("logs.reader"))), nil)
			if code := ErrorCode(err); code != CodeOwnerActsInvalid {
				t.Fatalf("code %q, err %v", code, err)
			}
		})
	}
}

func TestManifestV3RefusesOwnerActsRolesOutsideTheirRules(t *testing.T) {
	const origin = "https://console.logs.example.com"
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = v3Role(fmt.Sprintf("logs.r%d", i))
	}
	for name, ownerActs := range map[string]string{
		"no roles":                    v3OwnerActs(origin),
		"seventeen roles":             v3OwnerActs(origin, tooMany...),
		"a duplicate role":            v3OwnerActs(origin, v3Role("logs.reader"), v3Role("logs.reader")),
		"a role name of 24 bytes":     v3OwnerActs(origin, v3Role("logs.readerxxxxxxxxxxxxx")),
		"a leading digit":             v3OwnerActs(origin, v3Role("9logs.reader")),
		"one segment":                 v3OwnerActs(origin, v3Role("reader")),
		"an empty label":              v3OwnerActs(origin, `{"name":"logs.reader","label":"","acts":["human-role.designate"],"notice_contact":false}`),
		"a control in the label":      v3OwnerActs(origin, `{"name":"logs.reader","label":"Log\u0007reader","acts":["human-role.designate"],"notice_contact":false}`),
		"a bidi control in the label": v3OwnerActs(origin, `{"name":"logs.reader","label":"Log ‮reader","acts":["human-role.designate"],"notice_contact":false}`),
		"an empty description":        v3OwnerActs(origin, `{"name":"logs.reader","label":"Log reader","description":"","acts":["human-role.designate"],"notice_contact":false}`),
		"an unknown role member":      v3OwnerActs(origin, `{"name":"logs.reader","label":"Log reader","acts":["human-role.designate"],"notice_contact":false,"prepare_tool":"x"}`),
		"an unknown member":           `{"origin":"https://console.logs.example.com","roles":[` + v3Role("logs.reader") + `],"extra":1}`,
		"roles null":                  `{"origin":"https://console.logs.example.com","roles":null}`,
		"no origin":                   `{"roles":[` + v3Role("logs.reader") + `]}`,
		"not an object":               `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(v3Manifest(3, ownerActs), nil)
			if code := ErrorCode(err); code != CodeOwnerActsInvalid {
				t.Fatalf("code %q, err %v", code, err)
			}
		})
	}
}

func TestManifestV3AcceptsTheNeighboursOfEachRefusedRole(t *testing.T) {
	const origin = "https://console.logs.example.com"
	sixteen := make([]string, 16)
	for i := range sixteen {
		sixteen[i] = v3Role(fmt.Sprintf("logs.r%d", i))
	}
	for name, ownerActs := range map[string]string{
		"sixteen roles":           v3OwnerActs(origin, sixteen...),
		"a role name of 23 bytes": v3OwnerActs(origin, v3Role("logs.readerxxxxxxxxxxxx")),
		"two roles":               v3OwnerActs(origin, v3Role("logs.reader"), v3Role("logs.auditor")),
		"a description":           v3OwnerActs(origin, `{"name":"logs.reader","label":"Log reader","description":"Reads the audit log.","acts":["human-role.designate"],"notice_contact":false}`),
		"a different host":        v3OwnerActs("https://console.example.net", v3Role("logs.reader")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(v3Manifest(3, ownerActs), nil); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
}

func TestOwnerActsNullIsAnInvalidManifest(t *testing.T) {
	_, err := Load(v3Manifest(3, "null"), nil)
	if code := ErrorCode(err); code != CodeManifestInvalid {
		t.Fatalf("code %q, err %v", code, err)
	}
}

func TestOwnerActsIsAnUnknownMemberBeforeVersion3(t *testing.T) {
	ownerActs := v3OwnerActs("https://console.logs.example.com", v3Role("logs.reader"))
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			_, err := Load(v3Manifest(version, ownerActs), nil)
			if code := ErrorCode(err); code != CodeManifestInvalid {
				t.Fatalf("code %q, err %v", code, err)
			}
		})
	}
}

func TestManifestV3KeepsEveryVersion2Rule(t *testing.T) {
	// A version 2 fault is refused the same way under version 3.
	doc := `{"manifest_version":3,"app":{"id":"logs","origin":"https://logs.example.com"},"tools":[],"event_emitters":[]}`
	_, err := Load([]byte(doc), nil)
	if code := ErrorCode(err); code != CodeManifestInvalid {
		t.Fatalf("code %q, err %v", code, err)
	}
}

func TestACatalogServingVersions2And3ResolvesToVersion3(t *testing.T) {
	v2 := v3Manifest(2, "")
	v3 := v3Manifest(3, v3OwnerActs("https://console.logs.example.com", v3Role("logs.reader")))
	catalog, _ := json.Marshal(map[string]any{
		"catalog_version": 1,
		"app_id":          "logs",
		"variants": []map[string]any{
			{"manifest_version": 2, "url": "/v2.json", "digest": manifestDigest(v2)},
			{"manifest_version": 3, "url": "/v3.json", "digest": manifestDigest(v3)},
		},
	})
	files := map[string][]byte{DiscoveryCatalogPath: catalog, "/v2.json": v2, "/v3.json": v3}
	fetch := func(path string, _ int64) (int, []byte, error) {
		body, ok := files[path]
		if !ok {
			return 404, nil, nil
		}
		return 200, body, nil
	}
	variant, err := SelectVariant("https://logs.example.com", SupportedManifestVersions, fetch)
	if err != nil {
		t.Fatalf("SelectVariant: %v", err)
	}
	if variant.ManifestVersion != 3 || variant.URL != "https://logs.example.com/v3.json" {
		t.Fatalf("variant %d %s", variant.ManifestVersion, variant.URL)
	}
	variant, err = SelectVariant("https://logs.example.com", []int{1, 2}, fetch)
	if err != nil || variant.ManifestVersion != 2 {
		t.Fatalf("a version 2 client: %#v, %v", variant, err)
	}
}
