import Lean
import TrustWeb.Evidence
import TrustWeb.Operations
import TrustWeb.Core

/-!
# Every name the prose cites exists in the model

`lake build` reads `README.md`, `CLAIMS.md` and the model's Lean files, and
checks every text between backquotes, except file paths and shell commands
(a text with a slash, a hyphen, a line break or a leading hash, a name ending
in .lean, .md, .toml or .json, or the text lake build). It splits the text into identifiers and checks each one:

* an identifier with a leading dot, such as .release, must be a constructor
  of one of the model's inductive types other than its structures;
* an identifier that starts with a variable, such as c.org, must have the
  rest resolve in the model, as a field or a declaration;
* any other identifier must be the `TrustWeb` namespace itself, resolve in it
  directly or under one of the model's types or this check's own namespace,
  or be one of the few Lean names listed below.

An identifier with no letter, and the listed variables, keywords and
protocol names, are not checked. The build fails
on any identifier that does not pass.
-/

namespace TrustWeb.DocNames

open Lean Elab Command

/-- The backquote character. -/
def backquote : Char := Char.ofNat 96

/-- Identifiers that are not names: variables, keywords, the protocol's names
and the build's own library name. -/
def skipped : List String :=
  ["a", "b", "c", "g", "g'", "h", "h'", "i", "k", "m", "n", "o", "o'", "p", "pk",
   "r", "s", "s'", "s1", "s2", "t", "x", "L", "ask", "who", "approvals", "assign",
   "key", "as", "Prop", "sorry", "axiom", "native_decide", "opaque",
   "implemented_by", "controller_asserted_person", "nearest_human",
   "rotate_team_key", "DocCheck"]

/-- The Lean names outside `TrustWeb` that the prose means to cite. -/
def leanNames : List String :=
  ["propext", "Classical.choice", "Quot.sound", "List"]

/-- The model's types, and this check's own namespace: a name may resolve under
any of them. -/
def modelTypes : List Name :=
  [`Kind, `Issuer, `Team, `OrgKey, `Party, `Cert, `Membership, `ActKind, `Approver,
   `Rule, `Grant, `Invite, `Message, `State, `Person, `Valid, `ChainToRoot,
   `AnswersFor, `Step, `Reachable, `CoreStep, `CoreReachable, `Enrolment,
   `Assertion, `AdminTeamLocked, `DocNames]

/-- The model's inductive types: a leading-dot name must be a constructor of
one of them. -/
def inductives : List Name :=
  [`Kind, `Issuer, `Team, `OrgKey, `Party, `ActKind, `Approver, `Person, `Valid,
   `ChainToRoot, `AnswersFor, `Step, `Reachable, `CoreStep, `CoreReachable,
   `Enrolment]

def resolvesInModel (env : Environment) (n : Name) : Bool :=
  n == `TrustWeb || env.contains (`TrustWeb ++ n) || modelTypes.any fun t => env.contains (`TrustWeb ++ t ++ n)

def isConstructorOfModel (env : Environment) (n : Name) : Bool :=
  inductives.any fun t => (env.find? (`TrustWeb ++ t ++ n)).any (·.isCtor)

def isTokenChar (c : Char) : Bool :=
  c.isAlphanum || c == '_' || c == '\'' || c == '.'

/-- The runs of identifier characters in a text. -/
def runs (s : String) : List String :=
  let step := fun (st : Array String × String) (c : Char) =>
    if isTokenChar c then (st.1, st.2.push c)
    else if st.2.isEmpty then st else (st.1.push st.2, "")
  let (acc, cur) := s.toList.foldl step (#[], "")
  (if cur.isEmpty then acc else acc.push cur).toList

/-- Whether an identifier passes. -/
def passes (env : Environment) (raw : String) : Bool :=
  if !(raw.toList.any Char.isAlpha) then true
  else
    let body := String.ofList (raw.toList.dropWhile (· == '.'))
    if raw.startsWith "." then isConstructorOfModel env body.toName
    else
      match body.splitOn "." with
      | [] => true
      | head :: rest =>
        if skipped.contains head then
          rest.isEmpty || resolvesInModel env (String.intercalate "." rest).toName
        else resolvesInModel env body.toName || leanNames.contains body

/-- File paths and shell commands, which are not checked. -/
def isPathOrCommand (q : String) : Bool :=
  q.toList.any (fun c => c == '/' || c == '-' || c == '\n') || q.startsWith "#" ||
    q == "lake build" || [".lean", ".md", ".toml", ".json"].any fun (e : String) => q.endsWith e

/-- Every second piece of a text split at backquotes: the quoted texts. -/
def quoted : List String → List String
  | _ :: q :: rest => q :: quoted rest
  | _ => []

/-- The identifiers in a file's quoted texts that do not pass. -/
def failures (env : Environment) (text : String) : List String :=
  (quoted (text.splitOn (String.singleton backquote))).flatMap fun q =>
    if isPathOrCommand q then [] else
      ((runs q).filter fun r => !(passes env r)).map fun r => s!"{r} (in {q})"

/-- `#doc_names_resolve "f1" "f2" ...` fails if a file cites an identifier
that does not pass. -/
elab "#doc_names_resolve " files:str* : command => do
  let env ← getEnv
  let mut bad : Array String := #[]
  for f in files do
    let text ← liftIO <| IO.FS.readFile f.getString
    for q in failures env text do
      bad := bad.push s!"{f.getString}: {q}"
  unless bad.isEmpty do
    throwError m!"names cited in the prose that do not exist in the model:\n{String.intercalate "\n" bad.toList}"

#doc_names_resolve "README.md" "CLAIMS.md" "TrustWeb/Model.lean"
  "TrustWeb/Properties.lean" "TrustWeb/Abilities.lean" "TrustWeb/Operations.lean"
  "TrustWeb/Core.lean" "TrustWeb/Evidence.lean"

end TrustWeb.DocNames
