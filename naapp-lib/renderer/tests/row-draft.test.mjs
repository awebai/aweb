import test from "node:test";
import assert from "node:assert/strict";
import { createRowDraft } from "../row-draft.mjs";

const schema = {
  type: "object",
  properties: {
    finding: { type: "string", minLength: 1 },
    count: { type: "integer", minimum: 0 },
    status: { type: "string", enum: ["new", "done"] },
  },
  required: ["finding"],
  additionalProperties: false,
};
const record = {
  id: "r1",
  rev: 3,
  value: { finding: "Before", count: 2, status: "new", hidden: "private" },
};
function draft(operation = "update") {
  return createRowDraft({
    operation,
    record: operation === "add" ? null : record,
    fields: ["finding", "count", "status"],
    schema,
  });
}

test("patches carry the observed row revision and only changed authorized fields", () => {
  const model = draft();
  model.set("finding", "My input");
  assert.deepEqual(model.request().patch, { finding: "My input" });
  assert.equal(model.request().record_id, "r1");
  assert.equal(model.request().expected_rev, 3);
  assert.equal(JSON.stringify(model.request()).includes("private"), false);
  assert.equal(JSON.stringify(model.record).includes("private"), false);
  assert.throws(() => model.set("hidden", "no"));
});

test("unknown outcomes retain the exact request key and bytes", () => {
  const model = draft();
  model.set("finding", "My input");
  const first = model.request();
  assert.deepEqual(model.request(), first);
  assert.throws(() => model.set("finding", "Different bytes"));
  first.patch.finding = "Tampered caller copy";
  assert.equal(model.request().patch.finding, "My input");
});

test("a known conflict keeps input until an explicit rebase, which adopts untouched remote fields", () => {
  const model = draft();
  model.set("finding", "My input");
  const first = model.request();
  model.settle();
  assert.equal(model.record.rev, 3);
  assert.equal(model.values.finding, "My input");
  model.rebase({
    id: "r1",
    rev: 4,
    value: { finding: "Agent input", count: 5, status: "done" },
  });
  const second = model.request();
  assert.equal(second.expected_rev, 4);
  assert.notEqual(second.request_id, first.request_id);
  assert.deepEqual(second.patch, { finding: "My input" });
  assert.equal(model.values.count, 5);
  assert.equal(model.values.status, "done");
});

test("invalid typed input stays in the draft and prevents dispatch", () => {
  const model = draft();
  model.set("count", "not an integer");
  assert.equal(model.values.count, "not an integer");
  assert.deepEqual(model.errors, ["/count"]);
  assert.throws(
    () => model.request(),
    (error) => error.code === "schema_invalid",
  );
  model.set("count", 8);
  assert.deepEqual(model.request().patch, { count: 8 });
});

test("add and delete retain their own typed/idempotent operation shapes", () => {
  const added = draft("add");
  assert.throws(
    () => added.request(),
    (error) => error.code === "schema_invalid",
  );
  added.set("finding", "New row");
  assert.deepEqual(added.request().values, { finding: "New row" });
  assert.equal(added.request().expected_rev, undefined);
  const deleted = draft("delete");
  const request = deleted.request();
  assert.equal(request.record_id, "r1");
  assert.equal(request.expected_rev, 3);
  assert.equal(request.patch, undefined);
  assert.deepEqual(deleted.request(), request);
});

test("unchanged rows cannot create writes, and rebase cannot change the target row", () => {
  const model = draft();
  assert.throws(
    () => model.request(),
    (error) => error.code === "no_changes",
  );
  assert.throws(() => model.rebase({ ...record, id: "different" }));
});

test("draft validation retains its schema snapshot and record fields are ordinary data keys", () => {
  const projected = structuredClone(schema);
  const model = createRowDraft({
    operation: "update",
    record,
    fields: ["count"],
    schema: projected,
  });
  projected.properties.count.type = "string";
  model.set("count", "invalid");
  assert.deepEqual(model.errors, ["/count"]);
  const special = createRowDraft({
    operation: "add",
    record: null,
    fields: ["__proto__"],
    schema: JSON.parse(
      '{"type":"object","properties":{"__proto__":{"type":"string"}},"additionalProperties":false}',
    ),
  });
  special.set("__proto__", "a field value");
  assert.equal(Object.hasOwn(special.request().values, "__proto__"), true);
  assert.equal(special.request().values.__proto__, "a field value");
  assert.equal(
    Object.getPrototypeOf(special.request().values),
    Object.prototype,
  );
});
