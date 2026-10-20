// Real AWID integration driver. Authority arrives on stdin, never in argv.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/awebai/aw/awid"
)

type config struct {
	URL, Action, Key, TeamDID, MemberDID, MemberStableID, Certificate string
	Claims                                                            map[string]string
	Method, Path                                                      string
	Body                                                              json.RawMessage
}

func main() {
	var c config
	if err := json.NewDecoder(os.Stdin).Decode(&c); err != nil {
		panic(err)
	}
	seed, err := base64.StdEncoding.DecodeString(c.Key)
	if err != nil || len(seed) != ed25519.SeedSize {
		panic("invalid test authority")
	}
	key := ed25519.NewKeyFromSeed(seed)
	did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	client := awid.NewAWIDRegistryClient(nil, nil)
	ctx := context.Background()
	switch c.Action {
	case "create_team":
		_, err = client.CreateTeam(ctx, c.URL, "local", "new", "Review — <safe>", c.TeamDID, key)
	case "set_team_visibility":
		_, err = client.SetTeamVisibility(ctx, c.URL, "local", "base", "private", key)
	case "delete_team":
		err = client.DeleteTeam(ctx, c.URL, "local", "base", key, "test")
	case "register_certificate":
		var cert *awid.TeamCertificate
		cert, err = awid.DecodeTeamCertificateHeader(c.Certificate)
		if err == nil {
			err = client.RegisterCertificate(ctx, c.URL, "local", "base", cert, key)
		}
	case "revoke_certificate":
		err = client.RevokeCertificate(ctx, c.URL, "local", "base", c.Claims["certificate_id"], key)
	case "register":
		_, err = client.RegisterNamespaceAt(ctx, c.URL, "local", did, key)
	case "update_namespace":
		_, err = client.UpdateNamespaceDeliveryOriginAt(ctx, c.URL, "local", key, "https://delivery.example")
	case "delete_namespace":
		err = client.DeleteNamespaceAt(ctx, c.URL, "local", key, "test")
	case "register_address":
		_, err = client.RegisterAddressAt(ctx, c.URL, "local", "member", c.MemberStableID, c.MemberDID, key)
	case "delete_address":
		err = client.DeleteAddressAt(ctx, c.URL, "local", "member", key, "test")
	case "conditional_delete_address":
		var existing *awid.RegistryAddress
		existing, _, err = client.GetNamespaceAddressAt(ctx, c.URL, "local", "member")
		if err == nil {
			err = client.DeleteAddressIfMatchesAt(ctx, c.URL, "local", "member", existing.AddressID, existing.DIDAW, existing.CurrentDIDKey, key, "test")
		}
	default:
		err = client.ControllerRequest(ctx, c.Method, c.URL, c.Path, c.Claims, key, c.Body, nil)
	}
	status := 200
	if err != nil {
		var registry *awid.RegistryError
		if !errors.As(err, &registry) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		status = registry.StatusCode
	}
	json.NewEncoder(os.Stdout).Encode(map[string]int{"status": status})
}
