package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/approval"
)

var approvalOrigin, approvalRequester, approvalAdmission, approvalRecord string
var approvalResume bool

func init() {
	idRequestCmd.Flags().StringVar(&approvalOrigin, "approval-origin", "", "Known approval-service HTTPS origin for a needs-human response")
	idRequestCmd.Flags().StringVar(&approvalRequester, "approval-requester", "", "File containing this caller's canonical requester descriptor")
	idRequestCmd.Flags().StringVar(&approvalAdmission, "approval-admission", "", "File containing this caller's public admission certificate/chain")
	idRequestCmd.Flags().StringVar(&approvalRecord, "approval-record", "", "Private file retaining the original approval request and receipt")
	idRequestCmd.Flags().BoolVar(&approvalResume, "approval-resume", false, "Resume the original request from --approval-record")
}
func configuredApprovalClient(identity *localSigningIdentity, target string) (*approval.Client, error) {
	if approvalOrigin == "" {
		if approvalRequester != "" || approvalAdmission != "" || approvalRecord != "" || approvalResume {
			return nil, usageError("approval options require --approval-origin")
		}
		return nil, nil
	}
	if approvalRequester == "" || approvalAdmission == "" || approvalRecord == "" {
		return nil, usageError("approval requires --approval-requester, --approval-admission and --approval-record")
	}
	if len(identity.SigningKey) == 0 {
		return nil, usageError("approval requester requires a local identity signing key")
	}
	read := func(path string) (map[string]any, error) {
		raw, e := readFileBounded(path, maxResponseBytes)
		if e != nil {
			return nil, e
		}
		return proof.Parse(raw)
	}
	requester, e := read(approvalRequester)
	if e != nil {
		return nil, e
	}
	if requester["key"] != identity.DIDKey {
		return nil, errors.New("requester_mismatch")
	}
	admission, e := read(approvalAdmission)
	if e != nil {
		return nil, e
	}
	return &approval.Client{Origin: approvalOrigin, Requester: requester, Key: identity.SigningKey, Admission: admission, Retain: approvalRecordWriter(approvalRecord, approvalOrigin, target)}, nil
}
func readApprovalRecord(path, origin, target string) ([]byte, map[string]any, error) {
	raw, e := readFileBounded(path, maxResponseBytes)
	if e != nil {
		return nil, nil, e
	}
	record, e := proof.Parse(raw)
	if e != nil {
		return nil, nil, e
	}
	if record["origin"] != origin || record["enforcer"] != target {
		return nil, nil, errors.New("approval_record_mismatch")
	}
	value, ok := record["request_bytes"].(string)
	if !ok {
		return nil, nil, errors.New("approval_record_invalid")
	}
	original, e := base64.RawURLEncoding.Strict().DecodeString(value)
	if e != nil {
		return nil, nil, e
	}
	if base64.RawURLEncoding.EncodeToString(original) != value {
		return nil, nil, errors.New("approval_record_invalid")
	}
	receipt, _ := record["receipt"].(map[string]any)
	return original, receipt, nil
}
func approvalRecordWriter(path, origin, target string) func(string, []byte) error {
	return func(kind string, raw []byte) error {
		record := map[string]any{"v": 1, "origin": origin, "enforcer": target}
		previous, e := os.ReadFile(path)
		if e == nil {
			record, e = proof.Parse(previous)
			if e != nil {
				return e
			}
			if record["origin"] != origin || record["enforcer"] != target {
				return errors.New("approval_record_mismatch")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		switch kind {
		case "request":
			encoded := base64.RawURLEncoding.EncodeToString(raw)
			if prior, ok := record["request_bytes"]; ok && prior != encoded {
				return errors.New("approval_record_conflict: resume the original request or choose another record file")
			}
			record["request_bytes"] = encoded
		case "receipt":
			if record["request_bytes"] == nil {
				return errors.New("approval_record_invalid")
			}
			receipt, e := proof.Parse(raw)
			if e != nil {
				return e
			}
			record["receipt"] = receipt
		default:
			return fmt.Errorf("unknown approval record stage %q", kind)
		}
		data, e := json.MarshalIndent(record, "", "  ")
		if e != nil {
			return e
		}
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return e
		}
		tmp, e := os.CreateTemp(filepath.Dir(path), ".approval-*")
		if e != nil {
			return e
		}
		defer os.Remove(tmp.Name())
		if e = tmp.Chmod(0600); e == nil {
			_, e = tmp.Write(append(data, '\n'))
		}
		if e == nil {
			e = tmp.Sync()
		}
		closeErr := tmp.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		return os.Rename(tmp.Name(), path)
	}
}
