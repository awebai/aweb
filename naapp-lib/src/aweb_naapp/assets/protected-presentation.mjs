// A presentation guard only. The server's one operation registry supplies the
// codec schema; B2's existing serializer/digest remains the sole commitment.
import { canonical, coveredRequestDigest } from "./canonical-json.mjs";

const nonempty = value => typeof value === "string" && value.length > 0;
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const refused = () => { throw new Error("handoff_refused"); };

function fieldValid(value, schema) {
  if (value === null && schema.nullable === true) return true;
  if (schema.object) return validSubject(value, schema.object);
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
    return Array.isArray(value) && value.length <= (schema.maxItems ?? 64) && value.every(text) &&
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

function exact(value, names) {
  return object(value) && Object.keys(value).sort().join(",") === [...names].sort().join(",");
}

async function validAdmissionPolicy(policy, service, teams) {
  if (!exact(policy, ["version","digest","teams","root_selector","subject_kinds","member_role","bounds"]) ||
      !Number.isSafeInteger(policy.version) || policy.version < 1 ||
      !/^sha256:[0-9a-f]{64}$/.test(policy.digest) || policy.member_role !== "member" ||
      !exact(policy.root_selector,["kind","service_id"]) || policy.root_selector.kind !== "service_endorsed_root" ||
      policy.root_selector.service_id !== service ||
      !Array.isArray(policy.teams) || policy.teams.length === 0 ||
      !policy.teams.every((t,i)=>nonempty(t) && (i === 0 || policy.teams[i-1] < t)) ||
      !teams.every(t=>policy.teams.includes(t)) ||
      !Array.isArray(policy.subject_kinds) || policy.subject_kinds.length === 0 ||
      !policy.subject_kinds.every((k,i)=>["local_agent","registered_agent"].includes(k) && (i === 0 || policy.subject_kinds[i-1] < k)) ||
      !exact(policy.bounds,["max_active","rate_window_seconds","max_per_window"]) ||
      !Object.values(policy.bounds).every(v=>Number.isSafeInteger(v) && v > 0)) return false;
  const {digest,...unsigned} = policy;
  const bytes = new TextEncoder().encode("aweb.admission-policy/1\n" + canonical(unsigned));
  const sum = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return digest === "sha256:" + Array.from(sum,b=>b.toString(16).padStart(2,"0")).join("");
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
  if (request.approval_format !== "intent_v1" || spec.approval_format !== "intent_v1" || !object(spec.issuance) ||
      !exact(artifact, ["v", "type", "template", "delivery", "issuance_window"]) || artifact.v !== 1 ||
      artifact.type !== "aweb.protected-artifact-intent" || !object(artifact.template) ||
      !exact(artifact.delivery, ["audience", "method", "path"]) || artifact.delivery.audience !== request.audience ||
      artifact.delivery.method !== "POST" || !exact(artifact.issuance_window, ["not_before", "not_after"])) refused();
  const stamp = value => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0,19) === value.slice(0,19);
  const {not_before:start, not_after:until} = artifact.issuance_window;
  if (!stamp(start) || !stamp(until) || !(Date.parse(start) < Date.parse(until)) ||
      Date.parse(until) - Date.parse(start) > 86400000 || Date.parse(state.expires_at) > Date.parse(until)) refused();
  const templateRead = path => {
    let value = artifact.template;
    for (const part of path.split("/").slice(1)) {
      if (!object(value) || !Object.hasOwn(value, part)) refused();
      value = value[part];
    }
    return value;
  };
  const route = spec.issuance.fixed_route ?? templateRead(spec.issuance.route_field);
  if (artifact.delivery.path !== route) refused();
  for (const path of [...spec.issuance.issued_fields, ...(spec.issuance.expiry_field ? [spec.issuance.expiry_field] : [])]) {
    const parts = path.split("/").slice(1);
    let value = artifact.template;
    for (const part of parts.slice(0, -1)) {
      if (!object(value) || !object(value[part])) refused();
      value = value[part];
    }
    if (Object.hasOwn(value, parts.at(-1))) refused();
  }
  if (!validSubject(subject, spec.subject_schema)) refused();
  const guard = spec.presentation;
  if (!object(guard)) refused();
  const read = path => {
    let value = request;
    for (const part of path.split("/").slice(1)) {
      if (!object(value) || !Object.hasOwn(value, part)) refused();
      value = value[part];
    }
    return value;
  };
  for (const [path, names] of Object.entries(guard.exact ?? {})) {
    if (!exact(read(path), names)) refused();
  }
  for (const [path, choices] of Object.entries(guard.enums ?? {})) {
    if (!choices.includes(read(path))) refused();
  }
  for (const [path, template] of Object.entries(guard.templates ?? {})) {
    const expected = template.replace(/\{(\/[^}]+)\}/g, (_, source) => read(source));
    if (read(path) !== expected) refused();
  }
  for (const [path, fields] of Object.entries(guard.json_sha256 ?? {})) {
    const value = Object.fromEntries(Object.entries(fields).map(([key, source]) => [key, read(source)]));
    const sum = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(value))));
    if (read(path) !== Array.from(sum, b => b.toString(16).padStart(2, "0")).join("")) refused();
  }
  for (const [path, value] of Object.entries(guard.constants ?? {})) {
    if (canonical(read(path)) !== canonical(value)) refused();
  }
  for (const [left, right] of guard.equals ?? []) {
    if (canonical(read(left)) !== canonical(read(right))) refused();
  }
  for (const path of guard.nonempty ?? []) if (!nonempty(read(path))) refused();
  for (const path of guard.timestamps ?? []) {
    if (!nonempty(read(path)) || !Number.isFinite(Date.parse(read(path)))) refused();
  }
  for (const [path, pattern] of Object.entries(guard.nullable_patterns ?? {})) {
    const value = read(path);
    if (value !== null && (typeof value !== "string" || new RegExp(pattern).exec(value)?.[0] !== value)) refused();
  }
  if (guard.statement && read(guard.statement) !== spec.responsibility_statement) refused();
  if (guard.admission_policy) {
    const [policy, service, teams] = guard.admission_policy.map(read);
    if (!(await validAdmissionPolicy(policy, service, teams))) refused();
  }
  if (await coveredRequestDigest(payload) !== digest) refused();
  return {request, subject, artifact};
}
