import { canonical } from "./digests.mjs";
const refuse = (code) => {
  throw Object.assign(new Error(code), { code });
};

// The host supplies signed task metadata. Page schemas have no role in what a
// person reads beside a proposal value or choice.
export function decisionRows(cardOptions, evidence, value) {
  if (
    !Array.isArray(evidence.options) ||
    canonical(cardOptions) !== canonical(evidence.options)
  )
    refuse("options_mismatch");
  if (
    !Array.isArray(evidence.fields) ||
    evidence.fields.length < 1 ||
    evidence.fields.length > 32
  )
    refuse("fields_invalid");
  const fields = new Set(),
    labels = new Set();
  return evidence.fields.map(({ field, label, format }) => {
    if (
      typeof field !== "string" ||
      !field ||
      typeof label !== "string" ||
      !label ||
      fields.has(field) ||
      labels.has(label) ||
      !["text", "date", "number", "money_minor"].includes(format)
    )
      refuse("fields_invalid");
    fields.add(field);
    labels.add(label);
    if (!value || !Object.hasOwn(value, field)) refuse("field_missing");
    let currency = null;
    if (format === "money_minor") {
      currency = value.currency;
      if (
        typeof currency !== "string" ||
        !/^[A-Z]{3}$/.test(currency) ||
        !Intl.supportedValuesOf("currency").includes(currency)
      )
        refuse("currency_missing");
      if (!Number.isSafeInteger(value[field]) || Object.is(value[field], -0))
        refuse("money_invalid");
    }
    return [label, value[field], format, currency];
  });
}
