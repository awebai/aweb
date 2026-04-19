package main

import (
	"fmt"
	"strings"
)

func formatRegistryRead(out registryReadEnvelope) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Payload.Status))
	sb.WriteString(fmt.Sprintf("Operation:   %s\n", out.Payload.Operation))
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.Payload.RegistryURL))
	if out.AuthorityMode != "" {
		sb.WriteString(fmt.Sprintf("Authority:   %s\n", out.AuthorityMode))
	}
	if out.AuthoritySubject != "" {
		sb.WriteString(fmt.Sprintf("Subject:     %s\n", out.AuthoritySubject))
	}
	if out.Payload.Error != nil {
		sb.WriteString(fmt.Sprintf("Error:       %s\n", out.Payload.Error.Code))
		sb.WriteString(fmt.Sprintf("Message:     %s\n", out.Payload.Error.Message))
		return sb.String()
	}
	switch out.Payload.Operation {
	case "resolve-key":
		if out.Payload.DIDKey != nil {
			sb.WriteString(fmt.Sprintf("did:aw:      %s\n", out.Payload.DIDKey.DIDAW))
			sb.WriteString(fmt.Sprintf("did:key:     %s\n", out.Payload.DIDKey.CurrentDIDKey))
			if out.Payload.DIDKey.LogHead != nil {
				sb.WriteString(fmt.Sprintf("Log seq:     %d\n", out.Payload.DIDKey.LogHead.Seq))
				sb.WriteString(fmt.Sprintf("Operation:   %s\n", out.Payload.DIDKey.LogHead.Operation))
				sb.WriteString(fmt.Sprintf("Timestamp:   %s\n", out.Payload.DIDKey.LogHead.Timestamp))
			}
		}
	case "namespace-state":
		if out.Payload.Namespace != nil {
			sb.WriteString(fmt.Sprintf("Domain:      %s\n", out.Payload.Namespace.Domain))
			sb.WriteString(fmt.Sprintf("Controller:  %s\n", firstNonEmpty(out.Payload.Namespace.ControllerDID, "(none)")))
			sb.WriteString(fmt.Sprintf("Verified:    %s\n", out.Payload.Namespace.VerificationStatus))
		}
	case "resolve-address":
		if out.Payload.Address != nil {
			sb.WriteString(fmt.Sprintf("Address:     %s/%s\n", out.Payload.Address.Domain, out.Payload.Address.Name))
			sb.WriteString(fmt.Sprintf("did:aw:      %s\n", out.Payload.Address.DIDAW))
			sb.WriteString(fmt.Sprintf("did:key:     %s\n", out.Payload.Address.CurrentDIDKey))
			sb.WriteString(fmt.Sprintf("Reachable:   %s\n", out.Payload.Address.Reachability))
		}
	case "list-did-addresses", "list-addresses":
		if len(out.Payload.Addresses) == 0 {
			sb.WriteString("Addresses:   none\n")
			return sb.String()
		}
		sb.WriteString("Addresses:\n")
		for _, address := range out.Payload.Addresses {
			sb.WriteString(fmt.Sprintf("- %s/%s -> %s (%s, %s)\n",
				address.Domain,
				address.Name,
				address.DIDAW,
				address.CurrentDIDKey,
				address.Reachability,
			))
		}
	}
	return sb.String()
}
