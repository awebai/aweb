import Lean
import TrustWeb.Evidence
import TrustWeb.Operations
import TrustWeb.Core

/-!
# Every name the prose cites exists

`lake build` reads `README.md`, `CLAIMS.md` and the model's Lean files, takes
every text between backquotes that looks like a Lean name, and fails if one
resolves to no declaration. A name resolves if it, or it under one of the
namespaces below, is declared. Variable names, file names, keywords and the
protocol's own names are not Lean names and are skipped.
-/

namespace TrustWeb.DocNames

open Lean Elab Command

/-- The backquote character. -/
def backquote : Char := Char.ofNat 96

def isNameChar (c : Char) : Bool :=
  c.isAlphanum || c == '_' || c == '.' || c == '\''

def isNameToken (s : String) : Bool :=
  match s.toList with
  | [] => false
  | c :: _ => (c.isAlpha || c == '_') && s.toList.all isNameChar &&
      !([".lean", ".md", ".toml", ".json"].any fun (e : String) => s.endsWith e)

/-- Texts between backquotes that are not Lean names: variables, keywords,
the protocol's names and the build's own library name. -/
def skipped : List String :=
  ["a", "b", "c", "g", "h", "h'", "k", "m", "n", "o", "p", "s", "s'", "s1", "s2",
   "t", "x", "L", "ask", "who", "approvals", "assign", "key", "Prop",
   "sorry", "axiom", "native_decide", "opaque", "implemented_by",
   "controller_asserted_person", "nearest_human", "rotate_team_key", "DocCheck"]

/-- Where an unqualified name is looked up. -/
def namespaces : List Name :=
  [.anonymous, `TrustWeb, `TrustWeb.Step, `TrustWeb.AnswersFor, `TrustWeb.Valid,
   `TrustWeb.Person, `TrustWeb.ChainToRoot, `TrustWeb.State, `TrustWeb.Grant,
   `TrustWeb.Cert, `TrustWeb.Membership, `TrustWeb.Invite, `TrustWeb.Rule,
   `TrustWeb.Party, `TrustWeb.OrgKey, `TrustWeb.ActKind, `TrustWeb.Reachable,
   `TrustWeb.CoreStep, `TrustWeb.Assertion]

/-- Every second piece of a text split at backquotes: the quoted texts. -/
def quoted : List String → List String
  | _ :: q :: rest => q :: quoted rest
  | _ => []

/-- The cited names of a file's text that resolve to no declaration. -/
def unresolved (env : Environment) (text : String) : List String :=
  (quoted (text.splitOn (String.singleton backquote))).filter fun q =>
    isNameToken q && !(skipped.contains q) &&
      !(namespaces.any fun ns => env.contains (ns ++ q.toName))

/-- `#doc_names_resolve "f1" "f2" ...` fails if a file cites a name that does
not exist. -/
elab "#doc_names_resolve " files:str* : command => do
  let env ← getEnv
  let mut bad : Array String := #[]
  for f in files do
    let text ← liftIO <| IO.FS.readFile f.getString
    for q in unresolved env text do
      bad := bad.push s!"{f.getString}: {q}"
  unless bad.isEmpty do
    throwError m!"names cited in the prose that do not exist:\n{String.intercalate "\n" bad.toList}"

#doc_names_resolve "README.md" "CLAIMS.md" "TrustWeb/Model.lean"
  "TrustWeb/Properties.lean" "TrustWeb/Abilities.lean" "TrustWeb/Operations.lean"
  "TrustWeb/Core.lean" "TrustWeb/Evidence.lean"

end TrustWeb.DocNames
