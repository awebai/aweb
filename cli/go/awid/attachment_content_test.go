package awid

import (
 "encoding/json"
 "testing"
)

func TestAttachmentContentSurvivesTypedInnerReadWithoutChangingHeader(t *testing.T) {
 raw := []byte(`{"inner_version":2,"kind":"mail","message_id":"m","conversation_id":"c","created_at":"2026-10-18T00:00:00Z","from":{},"recipients":[],"body":"text","attachments":[{"id":"11111111-1111-4111-8111-111111111111","filename":"report.pdf","media_type":"application/pdf","size":9,"sha256":"d49bbd36ab4ddaf89bb051dc31b4ad2bc85c836a58e068e3819b0b297372f671","expires_at":"2026-11-18T00:00:00Z"}]}`)
 var inner E2EEInnerPayload
 if err := json.Unmarshal(raw,&inner); err != nil {t.Fatal(err)}
 encoded,err := json.Marshal(inner); if err != nil {t.Fatal(err)}
 var got map[string]any; if err:=json.Unmarshal(encoded,&got);err!=nil{t.Fatal(err)}
 if _,ok:=got["attachments"];!ok{t.Fatal("authenticated attachment content was discarded by typed inner read")}
 var old E2EEInnerPayload
 if err:=json.Unmarshal([]byte(`{"inner_version":2,"kind":"mail","message_id":"m","conversation_id":"c","created_at":"2026-10-18T00:00:00Z","from":{},"recipients":[],"body":"text"}`),&old);err!=nil{t.Fatal(err)}
 a,err:=e2eeInnerHeaderHash(inner);if err!=nil{t.Fatal(err)}
 b,err:=e2eeInnerHeaderHash(old);if err!=nil{t.Fatal(err)}
 if a!=b{t.Fatal("content-only descriptors changed the existing signed inner-header contract")}
}
