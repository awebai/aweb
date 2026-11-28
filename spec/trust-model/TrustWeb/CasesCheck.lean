import Lean
import TrustWeb.Emit

/-!
# The committed case file is the generator's output

The build's check that the cases in `docs/vectors/trust-web-cases-model-v2.json`
are exactly the cases `lake exe trust-web-cases` emits now, with the same
format and emitter. The model commit the file names is not compared: it is the
commit the file was generated at.
-/

namespace TrustWeb.CasesCheck

open Lean Elab Command

/-- `#cases_file_current "path"` fails unless the file's format, emitter and
cases are the generator's. -/
elab "#cases_file_current " f:str : command => do
  let text ← liftIO <| IO.FS.readFile f.getString
  let committed ← match Json.parse text with
    | .ok j => pure j
    | .error e => throwError m!"{f.getString} is not JSON: {e}"
  let fresh ← match TrustWeb.Emit.document "0000000000000000000000000000000000000000" with
    | .ok j => pure j
    | .error e => throwError m!"the generator refuses: {e}"
  for key in ["format", "cases"] do
    unless committed.getObjValD key == fresh.getObjValD key do
      throwError m!"{f.getString}: its {key} is not the generator's; regenerate it with lake exe trust-web-cases <model-commit>"
  unless (committed.getObjValD "model").getObjValD "emitter" == (fresh.getObjValD "model").getObjValD "emitter" do
    throwError m!"{f.getString}: its emitter is not the generator's"

#cases_file_current "../../docs/vectors/trust-web-cases-model-v2.json"

end TrustWeb.CasesCheck
