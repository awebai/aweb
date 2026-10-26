import { inputErrors } from "./input.mjs";

// A local draft is not authority. The host supplies projected schema/fields and
// rechecks all permissions, row revisions and idempotency on every request.
export function createRowDraft({ operation, record, fields, schema }) {
  if (!["add", "update", "delete"].includes(operation))
    throw new TypeError("Invalid row operation");
  schema = structuredClone(schema);
  const allowed = new Set(
    fields.filter((field) => Object.hasOwn(schema.properties || {}, field)),
  );
  const pick = (source) =>
    Object.fromEntries(
      [...allowed]
        .filter((field) => Object.hasOwn(source || {}, field))
        .map((field) => [field, structuredClone(source[field])]),
    );
  const validRecord = (value) =>
    value &&
    typeof value.id === "string" &&
    Number.isSafeInteger(value.rev) &&
    value.rev > 0;
  if (operation !== "add" && !validRecord(record))
    throw new TypeError("Invalid row revision");
  let base = structuredClone(record);
  let values = operation === "add" ? {} : pick(record.value);
  let attempt;
  const changes = () =>
    Object.fromEntries(
      [...allowed]
        .filter(
          (field) =>
            Object.hasOwn(values, field) &&
            JSON.stringify(values[field]) !==
              JSON.stringify(base?.value?.[field]),
        )
        .map((field) => [field, structuredClone(values[field])]),
    );
  function errors() {
    if (operation === "delete") return [];
    const candidate = operation === "add" ? values : changes();
    const missing = Object.keys(candidate)
      .filter((field) => candidate[field] === undefined)
      .map((field) => "/" + field.replaceAll("~", "~0").replaceAll("/", "~1"));
    if (operation === "add")
      return [...new Set([...missing, ...inputErrors(candidate, schema)])];
    return [
      ...new Set([
        ...missing,
        ...Object.keys(candidate).flatMap((field) =>
          inputErrors(
            candidate[field],
            schema.properties[field],
            "/" + field.replaceAll("~", "~0").replaceAll("/", "~1"),
          ),
        ),
      ]),
    ];
  }
  return {
    get values() {
      return structuredClone(values);
    },
    get record() {
      return base && { id: base.id, rev: base.rev, value: pick(base.value) };
    },
    get errors() {
      return errors();
    },
    get pending() {
      return !!attempt;
    },
    get changed() {
      return operation !== "update" || Object.keys(changes()).length > 0;
    },
    set(field, value) {
      if (!allowed.has(field)) throw { code: "field_denied" };
      if (attempt) throw { code: "unknown_outcome" };
      values = { ...values, [field]: structuredClone(value) };
    },
    request() {
      if (attempt) return structuredClone(attempt);
      const invalid = errors();
      if (invalid.length) throw { code: "schema_invalid", fields: invalid };
      const patch = changes();
      if (operation === "update" && !Object.keys(patch).length)
        throw { code: "no_changes" };
      attempt = {
        request_id: crypto.randomUUID(),
        ...(operation === "add"
          ? { values: structuredClone(values) }
          : {
              record_id: base.id,
              expected_rev: base.rev,
              ...(operation === "update" ? { patch } : {}),
            }),
      };
      return structuredClone(attempt);
    },
    settle() {
      attempt = undefined;
    },
    rebase(latest) {
      if (attempt) throw { code: "unknown_outcome" };
      if (operation === "add" || !validRecord(latest) || latest.id !== base.id)
        throw new TypeError("Invalid conflict row");
      const edited = changes();
      base = structuredClone(latest);
      values = { ...pick(latest.value), ...edited };
    },
  };
}
