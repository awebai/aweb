import test from "node:test";
import assert from "node:assert/strict";
import { inputErrors, typedValue, fieldValueText } from "../input.mjs";
test("form values follow the bounded input schema without unsafe integer or decimal coercion", () => {
  const schema = {
    type: "object",
    properties: {
      count: { type: "integer", minimum: 1, maximum: 8 },
      decimal: { type: "string", minLength: 1 },
      choice: { enum: ["a", "b"] },
    },
    required: ["count", "decimal"],
    additionalProperties: false,
  };
  assert.deepEqual(
    inputErrors({ count: 3, decimal: "1.25", choice: "a" }, schema),
    [],
  );
  assert.deepEqual(
    inputErrors({ count: 9, decimal: "", choice: "other", extra: 1 }, schema),
    ["/count", "/decimal", "/choice", "/extra"],
  );
  assert.equal(typedValue("9007199254740992", { type: "integer" }), undefined);
  assert.equal(typedValue("1.25", { type: "string" }), "1.25");
  assert.equal(typedValue("1,25", { type: "integer" }), undefined);
});

test("conflict values use the person's option and checkbox labels", () => {
  assert.equal(
    fieldValueText(
      { kind: "select", options: [{ value: "normal", label: "Normal" }] },
      "normal",
    ),
    "Normal",
  );
  assert.equal(fieldValueText({ kind: "checkbox" }, false), "Not checked");
  assert.equal(fieldValueText({ kind: "checkbox" }, true), "Checked");
});
