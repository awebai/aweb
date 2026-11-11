// Orders two object keys by Unicode code point, the order in which Go and
// Python sort the keys of a signed document. JavaScript's default string
// comparison orders by UTF-16 code unit, which puts a character outside the
// Basic Multilingual Plane (a surrogate pair, D800-DFFF) before U+E000-U+FFFF.
// An unpaired surrogate compares by its own value, as Python compares it.
export function compareByCodePoint(a: string, b: string): number {
  for (let i = 0; i < a.length && i < b.length;) {
    const x = a.codePointAt(i)!;
    const y = b.codePointAt(i)!;
    if (x !== y) return x < y ? -1 : 1;
    i += x > 0xffff ? 2 : 1;
  }
  return a.length - b.length;
}

// Canonical JSON for signed documents: object keys sorted by code point,
// arrays kept in order, no whitespace, non-ASCII text left unescaped. Only
// strings, booleans, null and safe integers are representable; anything else
// is refused with the caller's message.
export function canonicalJSONValue(value: unknown, unsupported: string): string {
  if (Array.isArray(value)) return `[${value.map(item => canonicalJSONValue(item, unsupported)).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort(compareByCodePoint).map(key => `${JSON.stringify(key)}:${canonicalJSONValue(obj[key], unsupported)}`).join(",")}}`;
  }
  if (typeof value === "string" || typeof value === "boolean" || value === null
      || (typeof value === "number" && Number.isSafeInteger(value))) return JSON.stringify(value);
  throw new Error(unsupported);
}
