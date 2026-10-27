package conformance_test

import (
 "bytes"
 "encoding/json"
 "reflect"
 "testing"
 awid "github.com/awebai/aw/awid"
)

type idChainCase struct {
 Name string `json:"name"`
 Chain []string `json:"chain"`
 Status string `json:"status"`
 Subject map[string]any `json:"subject"`
 SubjectPatch map[string]any `json:"subject_patch"`
 Expected awid.IDChainResult `json:"expected"`
 OriginalAuth string `json:"original_auth"`
 ExpectedRequest map[string]string `json:"expected_request"`
 Cache *struct { Age *float64 `json:"age_seconds"`; Refresh string `json:"refresh"` } `json:"cache"`
 ExpectedCacheMode string `json:"expected_cache_mode"`
 TreeLookup *bool `json:"tree_lookup"`
 PresentedChain *bool `json:"presented_chain"`
 StatusSource string `json:"status_source"`
 NamespaceAuthority map[string]any `json:"namespace_authority"`
}
type idChainVectors struct {
 Certificates map[string]struct { Signed map[string]any `json:"signed"` } `json:"certificates"`
 Statuses map[string]map[string]any `json:"status_fixtures"`
 Cases []idChainCase `json:"verification_cases"`
}
func TestIDChainFinalVectors(t *testing.T) {
 var v idChainVectors
 d:=json.NewDecoder(bytes.NewReader(readRootVector(t,"id-certificates-v1.json")));d.UseNumber()
 if err:=d.Decode(&v);err!=nil{t.Fatal(err)}
 for _,c:=range v.Cases{t.Run(c.Name,func(t *testing.T){
  values:=map[string]any{};for k,x:=range c.Subject{values[k]=x};for k,x:=range c.SubjectPatch{values[k]=x}
  text:=func(k string)string{s,_:=values[k].(string);return s}
  subject:=awid.IDChainSubject{ID:text("id"),DIDKey:text("did_key"),TeamMemberDIDAW:text("team_member_did_aw"),TeamMemberDIDKey:text("team_member_did_key")}
  var bundle map[string]any
  if len(c.Chain)>0&&(c.PresentedChain==nil||*c.PresentedChain){
   certs:=[]any{};for _,n:=range c.Chain{certs=append(certs,v.Certificates[n].Signed)}
   bundle=map[string]any{"v":1,"type":"aweb.id-chain","certificates":certs}
  }
  status:=v.Statuses[c.Status];domain:=status["domain"].(string)
  authority:=c.NamespaceAuthority
  if authority==nil{
   epochs:=status["namespace"].(map[string]any)["epochs"].([]any)
   current:=epochs[len(epochs)-1].(map[string]any)["did_key"]
   authority=map[string]any{"domain":domain,"dns_name":"_awid."+domain,"inherited":false,"controller_key":current}
  }
  age:=0.0;evidence:=&awid.IDChainEvidence{Status:status,NamespaceAuthority:authority,AgeSeconds:&age}
  if c.Cache!=nil{evidence.AgeSeconds=c.Cache.Age;evidence.RefreshFailed=c.Cache.Refresh=="failed"}
  if c.StatusSource=="caller"{evidence=nil}
  got:=awid.VerifyIDChain(bundle,subject,evidence,domain)
  if !reflect.DeepEqual(got,c.Expected){t.Fatalf("got %+v want %+v",got,c.Expected)}
  for key,human:=range map[string]bool{"ordinary":false,"human_required":true}{
   if got:=awid.IDRequestDisposition(got,subject,c.OriginalAuth=="passed",human);got!=c.ExpectedRequest[key]{t.Fatalf("%s=%s want %s",key,got,c.ExpectedRequest[key])}
  }
  if c.TreeLookup!=nil{request,err:=awid.IDStatusRequest(bundle,subject,domain);if err!=nil{t.Fatal(err)};if (request!=nil)!=*c.TreeLookup{t.Fatal("wrong status lookup decision")}}
  if c.ExpectedCacheMode!=""{if got:=awid.IDStatusCacheMode(c.Cache.Age,c.Cache.Refresh=="failed");got!=c.ExpectedCacheMode{t.Fatalf("cache=%s",got)}}
 })}
}
