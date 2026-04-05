package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

func formatIDRegister(v any) string {
	out := v.(idRegisterOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("did:aw:      %s\n", out.DIDAW))
	sb.WriteString(fmt.Sprintf("did:key:     %s\n", out.DIDKey))
	if strings.TrimSpace(out.Address) != "" {
		sb.WriteString(fmt.Sprintf("Address:     %s\n", out.Address))
	}
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	return sb.String()
}

func formatIDCreate(v any) string {
	out := v.(idCreateOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	if strings.TrimSpace(out.Address) != "" {
		sb.WriteString(fmt.Sprintf("Address:     %s\n", out.Address))
	}
	sb.WriteString(fmt.Sprintf("did:aw:      %s\n", out.DIDAW))
	sb.WriteString(fmt.Sprintf("did:key:     %s\n", out.DIDKey))
	sb.WriteString(fmt.Sprintf("Controller:  %s\n", out.ControllerDID))
	sb.WriteString(fmt.Sprintf("Identity:    %s\n", out.IdentityPath))
	sb.WriteString(fmt.Sprintf("Key:         %s\n", out.SigningKeyPath))
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryStatus))
	if strings.TrimSpace(out.RegistryURL) != "" {
		sb.WriteString(fmt.Sprintf("Registry URL: %s\n", out.RegistryURL))
	}
	if strings.TrimSpace(out.RegistryError) != "" {
		sb.WriteString(fmt.Sprintf("Registry Err: %s\n", out.RegistryError))
	}
	return sb.String()
}

func formatIDShow(v any) string {
	out := v.(idShowOutput)
	var sb strings.Builder
	if strings.TrimSpace(out.Alias) != "" {
		sb.WriteString(fmt.Sprintf("Alias:       %s\n", out.Alias))
	}
	if strings.TrimSpace(out.Address) != "" {
		sb.WriteString(fmt.Sprintf("Address:     %s\n", out.Address))
	}
	if strings.TrimSpace(out.DIDAW) != "" {
		sb.WriteString(fmt.Sprintf("did:aw:      %s\n", out.DIDAW))
	}
	if strings.TrimSpace(out.DIDKey) != "" {
		sb.WriteString(fmt.Sprintf("did:key:     %s\n", out.DIDKey))
	}
	if strings.TrimSpace(out.Custody) != "" {
		sb.WriteString(fmt.Sprintf("Custody:     %s\n", out.Custody))
	}
	if strings.TrimSpace(out.Lifetime) != "" {
		sb.WriteString(fmt.Sprintf("Lifetime:    %s\n", out.Lifetime))
	}
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryStatus))
	if strings.TrimSpace(out.RegistryURL) != "" {
		sb.WriteString(fmt.Sprintf("Registry URL: %s\n", out.RegistryURL))
	}
	if strings.TrimSpace(out.RegistryCurrentDIDKey) != "" {
		sb.WriteString(fmt.Sprintf("Registry DID: %s\n", out.RegistryCurrentDIDKey))
	}
	if strings.TrimSpace(out.RegistryError) != "" {
		sb.WriteString(fmt.Sprintf("Registry Err: %s\n", out.RegistryError))
	}
	return sb.String()
}

func formatIDResolve(v any) string {
	out := v.(idResolveOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("did:aw:      %s\n", out.DIDAW))
	sb.WriteString(fmt.Sprintf("did:key:     %s\n", out.CurrentDIDKey))
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	if out.LogHead != nil {
		sb.WriteString(fmt.Sprintf("Log seq:     %d\n", out.LogHead.Seq))
		sb.WriteString(fmt.Sprintf("Operation:   %s\n", out.LogHead.Operation))
		sb.WriteString(fmt.Sprintf("Timestamp:   %s\n", out.LogHead.Timestamp))
	}
	return sb.String()
}

func formatIDVerify(v any) string {
	out := v.(idVerifyOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("did:aw:      %s\n", out.DIDAW))
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	if out.EntryCount > 0 {
		sb.WriteString(fmt.Sprintf("Entries:     %d\n", out.EntryCount))
	}
	if strings.TrimSpace(out.CurrentDIDKey) != "" {
		sb.WriteString(fmt.Sprintf("did:key:     %s\n", out.CurrentDIDKey))
	}
	if strings.TrimSpace(out.Error) != "" {
		sb.WriteString(fmt.Sprintf("Error:       %s\n", out.Error))
	}
	return sb.String()
}

func formatIDNamespace(v any) string {
	out := v.(idNamespaceOutput)
	var sb strings.Builder
	if out.Namespace != nil {
		sb.WriteString(fmt.Sprintf("Domain:      %s\n", out.Namespace.Domain))
		sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
		sb.WriteString(fmt.Sprintf("Controller:  %s\n", firstNonEmpty(out.Namespace.ControllerDID, "(none)")))
		sb.WriteString(fmt.Sprintf("Verified:    %s\n", out.Namespace.VerificationStatus))
	} else {
		sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	}
	if len(out.Addresses) == 0 {
		sb.WriteString("Addresses:   none\n")
		return sb.String()
	}
	sb.WriteString("Addresses:\n")
	for _, address := range out.Addresses {
		sb.WriteString(fmt.Sprintf("- %s/%s → %s (%s, %s)\n",
			address.Domain,
			address.Name,
			address.DIDAW,
			address.CurrentDIDKey,
			address.Reachability,
		))
	}
	return sb.String()
}

func formatIDRotate(v any) string {
	out := v.(idRotateOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	if strings.TrimSpace(out.OldDID) != "" {
		sb.WriteString(fmt.Sprintf("Old DID:     %s\n", out.OldDID))
	}
	if strings.TrimSpace(out.NewDID) != "" {
		sb.WriteString(fmt.Sprintf("New DID:     %s\n", out.NewDID))
	}
	if strings.TrimSpace(out.RegistryURL) != "" {
		sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	}
	return sb.String()
}

func formatIDSign(v any) string {
	out := v.(idSignOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("did:key:     %s\n", out.DIDKey))
	sb.WriteString(fmt.Sprintf("Timestamp:   %s\n", out.Timestamp))
	sb.WriteString(fmt.Sprintf("Signature:   %s\n", out.Signature))
	return sb.String()
}

func formatIDRequest(v any) string {
	out := v.(idRequestOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %d\n", out.Status))
	if len(out.Headers) > 0 {
		sb.WriteString("Headers:\n")
		keys := make([]string, 0, len(out.Headers))
		for key := range out.Headers {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			value := out.Headers[key]
			sb.WriteString(fmt.Sprintf("- %s: %s\n", key, value))
		}
	}
	if out.Body == nil {
		return sb.String()
	}
	sb.WriteString("Body:\n")
	switch body := out.Body.(type) {
	case string:
		if strings.TrimSpace(body) == "" {
			sb.WriteString("(empty)\n")
		} else {
			sb.WriteString(body)
			if !strings.HasSuffix(body, "\n") {
				sb.WriteByte('\n')
			}
		}
	default:
		data, _ := json.MarshalIndent(body, "", "  ")
		sb.WriteString(string(data))
		sb.WriteByte('\n')
	}
	return sb.String()
}
