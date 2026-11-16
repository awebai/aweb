package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApprovalRequestFlagsAndPrivateOriginalRequestRecord(t *testing.T) {
	for _, name := range []string{"approval-origin", "approval-requester", "approval-admission", "approval-record", "approval-resume"} {
		if idRequestCmd.Flags().Lookup(name) == nil {
			t.Fatalf("missing requester flag %s", name)
		}
	}
	path := filepath.Join(t.TempDir(), "approval.json")
	retain := approvalRecordWriter(path, "https://awsign.com", "https://holder.example/humans")
	request := []byte(`{"deadline":1300,"requester":{"key":"original"}}`)
	if e := retain("request", request); e != nil {
		t.Fatal(e)
	}
	if e := retain("receipt", []byte(`{"version":1,"request_bytes":"original"}`)); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private record mode: %v %v", info, e)
	}
	original, receipt, e := readApprovalRecord(path, "https://awsign.com", "https://holder.example/humans")
	if e != nil {
		t.Fatal(e)
	}
	if receipt == nil {
		t.Fatal("retained receipt lost")
	}
	if string(original) != string(request) {
		t.Fatalf("original request changed: %s", original)
	}
	if e := retain("request", []byte(`{"deadline":1500}`)); e == nil {
		t.Fatal("retry silently replaced original act/deadline")
	}
	if _, _, e := readApprovalRecord(path, "https://other.example", "https://holder.example/humans"); e == nil {
		t.Fatal("record moved to another service")
	}
}
