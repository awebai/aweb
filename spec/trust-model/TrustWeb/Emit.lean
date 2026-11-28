import Lean.Data.Json
import TrustWeb.Run

/-!
# The case generator

Cases of format `aweb.trust-web-cases/2` for the runner in the aweb server's
tests. Each case is a setup of requests, a request, and what to observe after
it. The generator runs every request through `run`, which `step_iff_run` proves
equal to `Step`. It refuses to emit if a setup request is refused, or if a
request's outcome is not the one the case intends. So every emitted verdict,
and every premise named in a refusal, is the model's.
-/

namespace TrustWeb.Emit

open Lean (Json)

/-- The names the cases give keys, as the runner's seed cases do. -/
def keyName : Key → String
  | 1 => "alice"
  | 2 => "bot1"
  | 3 => "bot2"
  | 4 => "carol"
  | 5 => "dave"
  | k => s!"key{k}"

def alice : Key := 1
def bot1 : Key := 2
def bot2 : Key := 3
def carol : Key := 4
def dave : Key := 5

def orgName (o : Org) : String := s!"o{o}"

def teamJson : Team → Json
  | .admin => Json.str "admin"
  | .named n => Json.mkObj [("named", Json.num n)]

def kindName : Kind → String
  | .person => "person"
  | .agent => "agent"

def issuerJson : Issuer → Json
  | .root => Json.str "root"
  | .member p => Json.mkObj [("member", Json.str (keyName p))]

def certJson (c : Cert) : Json :=
  Json.mkObj [("org", Json.str (orgName c.org)), ("subject", Json.str (keyName c.subject)),
    ("kind", Json.str (kindName c.kind)), ("issuer", issuerJson c.issuer)]

def membershipJson (m : Membership) : Json :=
  Json.mkObj [("org", Json.str (orgName m.org)), ("team", teamJson m.team),
    ("member", Json.str (keyName m.member))]

def grantJson (g : Grant) : Json :=
  Json.mkObj [("session", Json.str s!"s{g.session}"), ("subject", Json.str (keyName g.subject)),
    ("org", Json.str (orgName g.org)), ("team", teamJson g.team), ("maySend", Json.bool g.maySend)]

def orgKeyJson : OrgKey → Json
  | .root o => Json.mkObj [("root", Json.str (orgName o))]
  | .team o t => Json.mkObj [("team", Json.mkObj [("org", Json.str (orgName o)), ("team", teamJson t)])]

def partyJson : Party → Except String Json
  | .dns o => .ok (Json.mkObj [("dns", Json.str (orgName o))])
  | .controller key => .ok (Json.mkObj [("controller", orgKeyJson key)])
  | .id k => .ok (Json.mkObj [("id", Json.str (keyName k))])
  | _ => .error "the runner has no form for this party"

/-- The act's name and arguments in the runner's form. -/
def actJson : Act → Except String (String × Json)
  | .createOrg o => .ok ("createOrg", Json.mkObj [("org", Json.str (orgName o))])
  | .registerByRoot c => .ok ("registerByRoot", Json.mkObj [("cert", certJson c)])
  | .registerByParent c => .ok ("registerByParent", Json.mkObj [("cert", certJson c)])
  | .revokeSelf c => .ok ("revokeSelf", Json.mkObj [("subject", Json.str (keyName c.subject))])
  | .revokeChild c => .ok ("revokeChild", Json.mkObj [("subject", Json.str (keyName c.subject))])
  | .revokeByOrg c => .ok ("revokeByOrg", Json.mkObj [("subject", Json.str (keyName c.subject))])
  | .admit m => .ok ("admit", Json.mkObj [("membership", membershipJson m)])
  | .remove m => .ok ("remove", Json.mkObj [("membership", membershipJson m)])
  | .mintGrant g => .ok ("mintGrant", Json.mkObj [("grant", grantJson g)])
  | .revokeGrant g => .ok ("revokeGrant", Json.mkObj [("grant", grantJson g)])
  | _ => .error "an act outside the first batch"

/-- An act that ends an identity's or a member's standing. -/
def revokes : Act → Bool
  | .revokeSelf _ | .revokeChild _ | .revokeByOrg _ | .remove _ => true
  | _ => false

/-- One request: who asks, for which act. The first batch has no held keys, so
no approvals. -/
structure Req where
  who : Party
  act : Act

/-- What a case observes after its request. -/
inductive Obs where
  | cert (k : Key)
  | valid (o : Org) (k : Key) (kind : Kind)
  | revoked (k : Key)
  | hasTeamCert (o : Org) (t : Team) (k : Key)
  | grant (session : Key)
  | grantLive (session : Key)

/-- An observation of a record, in the runner's form. -/
def Obs.json (s : State) : Obs → Json
  | .cert k =>
    Json.mkObj [("cert", Json.mkObj [("subject", Json.str (keyName k))]),
      ("is", match s.certs.find? (·.subject = k) with
        | some c => Json.mkObj [("org", Json.str (orgName c.org)), ("kind", Json.str (kindName c.kind)),
            ("issuer", issuerJson c.issuer)]
        | none => Json.null)]
  | .valid o k kind =>
    Json.mkObj [("valid", Json.mkObj [("org", Json.str (orgName o)), ("key", Json.str (keyName k)),
      ("kind", Json.str (kindName kind))]), ("is", Json.bool (decide (Valid s o k kind)))]
  | .revoked k =>
    Json.mkObj [("revoked", Json.mkObj [("key", Json.str (keyName k))]),
      ("is", Json.bool (decide (k ∈ s.revoked)))]
  | .hasTeamCert o t k =>
    Json.mkObj [("hasTeamCert", Json.mkObj [("org", Json.str (orgName o)), ("team", teamJson t),
      ("key", Json.str (keyName k))]), ("is", Json.bool (decide (HasTeamCert s o t k)))]
  | .grant n =>
    Json.mkObj [("grant", Json.mkObj [("session", Json.str s!"s{n}")]),
      ("is", Json.bool (s.grants.any (·.session = n)))]
  | .grantLive n =>
    Json.mkObj [("grantLive", Json.mkObj [("session", Json.str s!"s{n}")]),
      ("is", Json.bool (match s.grants.find? (·.session = n) with
        | some g => decide (GrantLive s g)
        | none => false))]

/-- A case: its name (without the `model-` prefix), setup, request, the premise
it is meant to be refused on (none if allowed), its admitted neighbour, and what
to observe. -/
structure Case where
  name : String
  setup : List Req
  req : Req
  refusedOn : Option String := none
  neighbour : Option String := none
  observe : List Obs

def emptyRecord : State := ⟨[], [], [], [], [], [], [], [], [], []⟩

def reqJson (r : Req) : Except String Json := do
  let (name, args) ← actJson r.act
  return Json.mkObj [("who", ← partyJson r.who), ("act", Json.str name), ("args", args)]

/-- Run a case and render it, or say why it cannot be emitted. -/
def Case.json (c : Case) : Except String Json := do
  -- Cases run under `builtRule`: with no held key, no case consults the rule.
  let mut s := emptyRecord
  for r in c.setup do
    match run builtRule s r.who [] r.act with
    | .ok s' => s := s'
    | .error p => throw s!"{c.name}: setup refused on {p}"
  let (after, expect) ← match run builtRule s c.req.who [] c.req.act, c.refusedOn with
    | .ok s', none => pure (s', Json.mkObj [("result", Json.str "allowed")])
    | .error p, some q =>
      if p = q then pure (s, Json.mkObj [("result", Json.str "refused"), ("premise", Json.str p)])
      else throw s!"{c.name}: refused on {p}, meant {q}"
    | .ok _, some q => throw s!"{c.name}: allowed, meant refused on {q}"
    | .error p, none => throw s!"{c.name}: refused on {p}, meant allowed"
  let setup ← c.setup.mapM reqJson
  let (actName, args) ← actJson c.req.act
  let revokes := (c.req :: c.setup).any (fun r => revokes r.act)
  let fields : List (String × Json) :=
    [("id", Json.str s!"model-{c.name}"), ("source", Json.str "emitted"),
     ("status", Json.str "implemented"), ("rule", Json.str "any"),
     ("setup", Json.arr setup.toArray), ("who", ← partyJson c.req.who),
     ("act", Json.str actName), ("args", args), ("expect", expect)] ++
    (if revokes then [("propagation", Json.str "after")] else []) ++
    (match c.neighbour with
     | some n => [("neighbour", Json.str s!"model-{n}")]
     | none => []) ++
    [("observe", Json.arr (c.observe.map (Obs.json after)).toArray)]
  return Json.mkObj fields

/-! ## The first batch -/

def dns (o : Org) : Party := .dns o
def rootOf (o : Org) : Party := .controller (.root o)
def teamOf (o : Org) (n : Nat) : Party := .controller (.team o (.named n))

def personCert (k : Key) : Cert := ⟨1, k, .person, .root⟩
def agentCert (k p : Key) : Cert := ⟨1, k, .agent, .member p⟩
def carolIn (n : Nat) : Membership := ⟨1, .named n, carol⟩
def grantS1 : Grant := ⟨1, carol, 1, .named 1, true⟩

def org1 : List Req := [⟨dns 1, .createOrg 1⟩]
def org12 : List Req := org1 ++ [⟨dns 2, .createOrg 2⟩]
def withAlice : List Req := org1 ++ [⟨rootOf 1, .registerByRoot (personCert alice)⟩]
def withBot1 : List Req := withAlice ++ [⟨.id alice, .registerByParent (agentCert bot1 alice)⟩]
def aliceRevoked (setup : List Req) : List Req := setup ++ [⟨.id alice, .revokeSelf (personCert alice)⟩]
def withCarol : List Req := org1 ++ [⟨teamOf 1 1, .admit (carolIn 1)⟩]
def withGrant : List Req := withCarol ++ [⟨.id carol, .mintGrant grantS1⟩]

def certObs (k : Key) (kind : Kind) : List Obs := [.cert k, .valid 1 k kind]
def revokeObs (k : Key) (kind : Kind) : List Obs := [.revoked k, .valid 1 k kind]

def cases : List Case := [
  -- registerByRoot
  { name := "register-person-by-root", setup := org12,
    req := ⟨rootOf 1, .registerByRoot (personCert alice)⟩, observe := certObs alice .person },
  { name := "register-person-by-other-org-root-refused", setup := org12,
    req := ⟨rootOf 2, .registerByRoot (personCert alice)⟩,
    refusedOn := "registerByRoot.Authorised", neighbour := "register-person-by-root",
    observe := [.cert alice] },
  { name := "register-person-issued-by-member-refused", setup := org12,
    req := ⟨rootOf 1, .registerByRoot ⟨1, alice, .person, .member bot1⟩⟩,
    refusedOn := "registerByRoot.Issuer", neighbour := "register-person-by-root",
    observe := [.cert alice] },
  { name := "register-person-in-missing-org-refused", setup := org12,
    req := ⟨rootOf 1, .registerByRoot ⟨3, alice, .person, .root⟩⟩,
    refusedOn := "registerByRoot.OrgExists", neighbour := "register-person-by-root",
    observe := [.cert alice] },
  { name := "register-person-twice-refused", setup := org12 ++ [⟨rootOf 1, .registerByRoot (personCert alice)⟩],
    req := ⟨rootOf 1, .registerByRoot (personCert alice)⟩,
    refusedOn := "registerByRoot.Fresh", neighbour := "register-person-by-root",
    observe := [.cert alice] },
  -- registerByParent
  { name := "register-agent-by-person-parent", setup := withAlice,
    req := ⟨.id alice, .registerByParent (agentCert bot1 alice)⟩, observe := certObs bot1 .agent },
  { name := "register-agent-by-agent-parent", setup := withBot1,
    req := ⟨.id bot1, .registerByParent (agentCert bot2 bot1)⟩, observe := certObs bot2 .agent },
  { name := "register-person-by-agent-parent-refused", setup := withBot1,
    req := ⟨.id bot1, .registerByParent ⟨1, bot2, .person, .member bot1⟩⟩,
    refusedOn := "registerByParent.MayIssue", neighbour := "register-agent-by-agent-parent",
    observe := [.cert bot2] },
  { name := "register-agent-by-revoked-parent-refused", setup := aliceRevoked withAlice,
    req := ⟨.id alice, .registerByParent (agentCert bot1 alice)⟩,
    refusedOn := "registerByParent.Valid", neighbour := "register-agent-by-person-parent",
    observe := [.cert bot1] },
  { name := "register-agent-by-orphaned-agent-parent-refused", setup := aliceRevoked withBot1,
    req := ⟨.id bot1, .registerByParent (agentCert bot2 bot1)⟩,
    refusedOn := "registerByParent.Valid", neighbour := "register-agent-by-agent-parent",
    observe := [.cert bot2] },
  { name := "register-agent-issued-by-root-refused", setup := withAlice,
    req := ⟨.id alice, .registerByParent ⟨1, bot1, .agent, .root⟩⟩,
    refusedOn := "registerByParent.Issuer", neighbour := "register-agent-by-person-parent",
    observe := [.cert bot1] },
  { name := "register-agent-for-another-parent-refused", setup := withBot1,
    req := ⟨.id bot1, .registerByParent (agentCert bot2 alice)⟩,
    refusedOn := "registerByParent.Asker", neighbour := "register-agent-by-agent-parent",
    observe := [.cert bot2] },
  { name := "register-agent-twice-refused", setup := withBot1,
    req := ⟨.id alice, .registerByParent (agentCert bot1 alice)⟩,
    refusedOn := "registerByParent.Fresh", neighbour := "register-agent-by-person-parent",
    observe := [.cert bot1] },
  -- revokeSelf
  { name := "revoke-self", setup := withAlice,
    req := ⟨.id alice, .revokeSelf (personCert alice)⟩, observe := revokeObs alice .person },
  { name := "revoke-self-unregistered-refused", setup := withAlice,
    req := ⟨.id carol, .revokeSelf (personCert carol)⟩,
    refusedOn := "revokeSelf.Registered", neighbour := "revoke-self",
    observe := [.revoked carol] },
  { name := "revoke-self-by-another-refused", setup := withBot1,
    req := ⟨.id bot1, .revokeSelf (personCert alice)⟩,
    refusedOn := "revokeSelf.Asker", neighbour := "revoke-self",
    observe := [.revoked alice] },
  -- revokeChild
  { name := "revoke-child-by-parent", setup := withBot1,
    req := ⟨.id alice, .revokeChild (agentCert bot1 alice)⟩, observe := revokeObs bot1 .agent },
  { name := "revoke-child-by-revoked-parent-refused", setup := aliceRevoked withBot1,
    req := ⟨.id alice, .revokeChild (agentCert bot1 alice)⟩,
    refusedOn := "revokeChild.Valid", neighbour := "revoke-child-by-parent",
    observe := [.revoked bot1] },
  { name := "revoke-child-unregistered-refused", setup := withBot1,
    req := ⟨.id alice, .revokeChild (agentCert bot2 alice)⟩,
    refusedOn := "revokeChild.Registered", neighbour := "revoke-child-by-parent",
    observe := [.revoked bot2] },
  { name := "revoke-child-issued-by-root-refused", setup := withBot1,
    req := ⟨.id alice, .revokeChild (personCert alice)⟩,
    refusedOn := "revokeChild.Issuer", neighbour := "revoke-child-by-parent",
    observe := [.revoked alice] },
  { name := "revoke-child-by-non-parent-refused", setup := withBot1,
    req := ⟨.id bot1, .revokeChild (agentCert bot1 alice)⟩,
    refusedOn := "revokeChild.Asker", neighbour := "revoke-child-by-parent",
    observe := [.revoked bot1] },
  -- revokeByOrg
  { name := "revoke-by-org", setup := withAlice,
    req := ⟨rootOf 1, .revokeByOrg (personCert alice)⟩, observe := revokeObs alice .person },
  { name := "revoke-by-org-unregistered-refused", setup := withAlice,
    req := ⟨rootOf 1, .revokeByOrg (personCert carol)⟩,
    refusedOn := "revokeByOrg.Registered", neighbour := "revoke-by-org",
    observe := [.revoked carol] },
  { name := "revoke-by-other-org-refused", setup := withAlice ++ [⟨dns 2, .createOrg 2⟩],
    req := ⟨rootOf 2, .revokeByOrg (personCert alice)⟩,
    refusedOn := "revokeByOrg.Authorised", neighbour := "revoke-by-org",
    observe := [.revoked alice] },
  -- admit
  { name := "admit-member", setup := org1,
    req := ⟨teamOf 1 1, .admit (carolIn 1)⟩, observe := [.hasTeamCert 1 (.named 1) carol] },
  { name := "admit-by-other-team-key-refused", setup := org1,
    req := ⟨teamOf 1 2, .admit (carolIn 1)⟩,
    refusedOn := "admit.Authorised", neighbour := "admit-member",
    observe := [.hasTeamCert 1 (.named 1) carol] },
  { name := "admit-to-admin-team-refused", setup := org1,
    req := ⟨.controller (.team 1 .admin), .admit ⟨1, .admin, carol⟩⟩,
    refusedOn := "admit.NotAdminTeam", neighbour := "admit-member",
    observe := [.hasTeamCert 1 .admin carol] },
  { name := "admit-local-member-to-second-team-refused", setup := withCarol,
    req := ⟨teamOf 1 2, .admit (carolIn 2)⟩,
    refusedOn := "admit.OneTeamIfLocal", neighbour := "admit-member",
    observe := [.hasTeamCert 1 (.named 2) carol] },
  -- remove
  { name := "remove-member", setup := withCarol,
    req := ⟨teamOf 1 1, .remove (carolIn 1)⟩, observe := [.hasTeamCert 1 (.named 1) carol] },
  { name := "remove-by-other-team-key-refused", setup := withCarol,
    req := ⟨teamOf 1 2, .remove (carolIn 1)⟩,
    refusedOn := "remove.Authorised", neighbour := "remove-member",
    observe := [.hasTeamCert 1 (.named 1) carol] },
  { name := "remove-member-ends-its-grant", setup := withGrant,
    req := ⟨teamOf 1 1, .remove (carolIn 1)⟩,
    observe := [.hasTeamCert 1 (.named 1) carol, .grantLive 1] },
  -- mintGrant
  { name := "mint-grant", setup := withCarol,
    req := ⟨.id carol, .mintGrant grantS1⟩, observe := [.grant 1] },
  { name := "mint-grant-after-removal-refused", setup := withCarol ++ [⟨teamOf 1 1, .remove (carolIn 1)⟩],
    req := ⟨.id carol, .mintGrant grantS1⟩,
    refusedOn := "mintGrant.InTeam", neighbour := "mint-grant", observe := [.grant 1] },
  { name := "mint-grant-for-another-refused", setup := withCarol,
    req := ⟨.id dave, .mintGrant grantS1⟩,
    refusedOn := "mintGrant.Asker", neighbour := "mint-grant", observe := [.grant 1] },
  { name := "mint-grant-reusing-session-refused", setup := withGrant,
    req := ⟨.id carol, .mintGrant grantS1⟩,
    refusedOn := "mintGrant.FreshSession", neighbour := "mint-grant", observe := [.grant 1] },
  -- revokeGrant
  { name := "revoke-grant", setup := withGrant,
    req := ⟨.id carol, .revokeGrant grantS1⟩, observe := [.grant 1] },
  { name := "revoke-grant-by-another-refused", setup := withGrant,
    req := ⟨.id dave, .revokeGrant grantS1⟩,
    refusedOn := "revokeGrant.Asker", neighbour := "revoke-grant", observe := [.grant 1] },
  { name := "revoke-grant-not-minted-refused", setup := withCarol,
    req := ⟨.id carol, .revokeGrant grantS1⟩,
    refusedOn := "revokeGrant.Stands", neighbour := "revoke-grant", observe := [.grant 1] }
]

/-- The whole file, given the model commit it was generated at. -/
def document (commit : String) : Except String Json := do
  let cs ← cases.mapM (·.json)
  return Json.mkObj [
    ("format", Json.str "aweb.trust-web-cases/2"),
    ("status", Json.str "experimental"),
    ("description", Json.str "Cases emitted from the trust-web model (spec/trust-model) by lake exe trust-web-cases. Every verdict and every refusal's premise is computed by the model's executable step, which the model proves equal to its Step relation (step_iff_run, run_error_premise)."),
    ("model", Json.mkObj [("path", Json.str "spec/trust-model"), ("commit", Json.str commit),
      ("emitter", Json.str "lake exe trust-web-cases")]),
    ("cases", Json.arr cs.toArray)]

end TrustWeb.Emit

open TrustWeb.Emit in
/-- `trust-web-cases <model-commit>` prints the case file. -/
def main (args : List String) : IO UInt32 := do
  match args with
  | [commit] =>
    if commit.length != 40 || !commit.all (fun c => c.isDigit || ('a' ≤ c && c ≤ 'f')) then
      IO.eprintln "the model commit must be 40 lowercase hex characters"
      return 2
    match document commit with
    | .ok j =>
      IO.println j.pretty
      return 0
    | .error e =>
      IO.eprintln e
      return 1
  | _ =>
    IO.eprintln "usage: trust-web-cases <model-commit>"
    return 2
