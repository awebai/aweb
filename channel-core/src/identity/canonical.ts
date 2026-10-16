// Canonical JSON for signed documents: object keys sorted, arrays kept in
// order, no whitespace, non-ASCII text left unescaped. Only strings, booleans,
// null and safe integers are representable; anything else is refused with the
// caller's message.
export function canonicalJSONValue(value: unknown, unsupported: string): string {
  if (Array.isArray(value)) return `[${value.map(item => canonicalJSONValue(item, unsupported)).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map(key => `${JSON.stringify(key)}:${canonicalJSONValue(obj[key], unsupported)}`).join(",")}}`;
  }
  if (typeof value === "string" || typeof value === "boolean" || value === null
      || (typeof value === "number" && Number.isSafeInteger(value))) return JSON.stringify(value);
  throw new Error(unsupported);
}
