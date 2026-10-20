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
test("calendar dates stay on their written day west of UTC; date-times retain time", () => {
  assert.equal(
    valueText("2026-10-20", "date", "en", "America/Los_Angeles"),
    "Oct 20, 2026",
  );
  assert.match(
    valueText("2026-10-20T10:00:00Z", "date-time", "en", "America/Los_Angeles"),
    /Oct 20.*3:00/,
  );
});
test("money uses the record currency minor-unit scale without losing large integers", () => {
  assert.equal(
    valueText(12345, "money_minor", "en", undefined, "EUR"),
    "€123.45",
  );
  assert.equal(
    valueText(12345, "money_minor", "en", undefined, "JPY"),
    "¥12,345",
  );
  assert.equal(valueText(-25, "money_minor", "en", undefined, "EUR"), "-€0.25");
  assert.equal(
    valueText("900719925474099100", "money_minor", "en", undefined, "EUR"),
    "€9,007,199,254,740,991.00",
  );
  assert.equal(
    valueText(12345, "money_minor", "en", undefined, "not-a-currency"),
    "123.45",
  );
});
