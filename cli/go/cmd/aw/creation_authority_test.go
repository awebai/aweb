package main

import (
 "testing"
)

func TestCreationAuthorityDecision(t *testing.T) {
 const notice = "Using this workspace's signed invitation; the supplied agent API key is not creating the child."
 const a5 = "This is an agent's workspace key. Run creation from that agent's workspace, or use a setup key from the dashboard. To create here from another workspace, use aw init --join-from <workspace>."
 for _, tc := range []struct{
 name string
 input creationAuthorityInput
 mode string
 notice string
 refusal string
 }{
 {"stored key is not an input",creationAuthorityInput{SourceTeam:"dev:example.com"},"invitation","",""},
 {"no key with signer",creationAuthorityInput{SourceTeam:"dev:example.com",RequestedTeam:"dev:example.com"},"invitation","",""},
 {"workspace key with signer",creationAuthorityInput{SuppliedKey:true,KeyKind:"workspace",SourceTeam:"dev:example.com",RequestedTeam:"dev:example.com"},"invitation",notice,""},
 {"workspace key without signer",creationAuthorityInput{SuppliedKey:true,KeyKind:"workspace"},"","",a5},
 {"workspace key wrong team",creationAuthorityInput{SuppliedKey:true,KeyKind:"workspace",SourceTeam:"dev:example.com",RequestedTeam:"ops:example.com"},"","","This workspace belongs to dev:example.com, not ops:example.com. "+a5},
 {"person key wins",creationAuthorityInput{SuppliedKey:true,KeyKind:"person",SourceTeam:"dev:example.com"},"api","",""},
 {"absent field older server",creationAuthorityInput{SuppliedKey:true,SourceTeam:"dev:example.com"},"api","",""},
 {"unknown field older behavior",creationAuthorityInput{SuppliedKey:true,KeyKind:"future",SourceTeam:"dev:example.com"},"api","",""},
 {"stale team kind is unknown",creationAuthorityInput{SuppliedKey:true,KeyKind:"team",SourceTeam:"dev:example.com"},"api","",""},
 {"local controller",creationAuthorityInput{SourceTeam:"dev:example.com",LocalController:true},"controller","",""},
 {"founding with workspace key",creationAuthorityInput{SuppliedKey:true,KeyKind:"workspace",Founding:true,SourceTeam:"dev:example.com"},"","","An agent's workspace key cannot found a new team. Use a setup key from the dashboard, a namespace controller with aw team admin create --byot --namespace <domain>, or the signed aw id team create --hosted operation."},
 } {
 t.Run(tc.name,func(t *testing.T){
 got,err:=decideCreationAuthority(tc.input)
 if tc.refusal!="" {if err==nil || err.Error()!=tc.refusal {t.Fatalf("error=%v, want %q",err,tc.refusal)};return}
 if err!=nil || got.Mode!=tc.mode || got.Notice!=tc.notice {t.Fatalf("decision=%+v err=%v",got,err)}
 })
 }
}
