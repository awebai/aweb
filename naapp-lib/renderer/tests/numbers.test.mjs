import test from "node:test";
import assert from "node:assert/strict";
import { valueText } from "../dom.mjs";
test("decimal-string data retains every fractional digit in English number formatting", () => {
  assert.equal(
    valueText("1234567.123456789", "number", "en"),
    "1,234,567.123456789",
  );
  assert.equal(valueText("-0.25", "number", "en"), "-0.25");
  assert.equal(valueText(1234567, "money_minor", "en"), "12,345.67");
});
