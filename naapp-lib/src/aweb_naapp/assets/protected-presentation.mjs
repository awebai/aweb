// A presentation guard only. The server's one operation registry supplies the
// codec schema; B2's existing serializer/digest remains the sole commitment.
import { canonical, coveredRequestDigest } from "./canonical-json.mjs";

const nonempty = value => typeof value === "string" && value.length > 0;
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const refused = () => { throw new Error("handoff_refused"); };

function fieldValid(value, schema) {
  if (schema.integer) {
    return Number.isSafeInteger(value) && value >= schema.integer[0] && value <= schema.integer[1];
  }
  if (schema.enum) return schema.enum.includes(value);
  const text = item => {
    if (typeof item !== "string" || typeof schema.pattern !== "string") return false;
    const matched = new RegExp(schema.pattern).exec(item);
    return matched !== null && matched[0] === item;
  };
  if (schema.list) {
    return Array.isArray(value) && value.length <= 64 && value.every(text) &&
      value.every((item, index) => index === 0 || value[index - 1] < item);
  }
  return text(value);
}

function validSubject(subject, schema) {
  if (!object(subject) || !object(schema) || !object(schema.fields) || !Array.isArray(schema.required)) return false;
  const required = new Set(schema.required);
  const conditional = new Set();
  for (const [field, value, names] of schema.when ?? []) {
    for (const name of names) conditional.add(name);
    if (subject[field] === value) for (const name of names) required.add(name);
  }
  if ([...required].some(name => !Object.hasOwn(subject, name))) return false;
  return Object.keys(subject).every(name => Object.hasOwn(schema.fields, name) &&
    (!conditional.has(name) || required.has(name)) && fieldValid(subject[name], schema.fields[name])) &&
    (subject.team_seq_first === undefined || subject.team_seq_first <= subject.team_seq_last);
}

export async function validateProtectedPresentation(state, handoffId, table) {
  const {payload, digest} = state;
  const request = payload?.request;
  const subject = request?.subject;
  const artifact = request?.artifact;
  const spec = table?.[`${request?.operation}|${request?.variant}`];
  if (state.mode !== "governance" || state.handoff_id !== handoffId || state.state !== "pending" ||
      !nonempty(state.operation_id) || request?.operation_id !== state.operation_id ||
      !/^[0-9a-f]{64}$/.test(digest) || !nonempty(state.expires_at) || !Number.isFinite(Date.parse(state.expires_at)) ||
      !nonempty(payload?.policy?.ref) || !Number.isSafeInteger(payload?.policy?.version) || payload.policy.version < 1 ||
      !spec || !spec.consumer_available || spec.rule !== "live_floor" ||
      request?.scope?.authority?.kind !== spec.key_role) refused();
  if (spec.family === "owner_act") {
    if (!validSubject(subject, spec.subject_schema) || artifact?.v !== 1 || artifact?.type !== "aweb.owner-act" ||
        artifact.act !== request.operation || artifact.team_id !== request.scope.authority.id ||
        artifact.aud !== request.audience || !object(artifact.subject) ||
        canonical(subject) !== canonical(artifact.subject)) refused();
  } else {
    // A new family must provide its actual typed codec/presentation binding;
    // registering a name in the table alone never enables an approval button.
    refused();
  }
  if (await coveredRequestDigest(payload) !== digest) refused();
  return {request, subject, artifact};
}
