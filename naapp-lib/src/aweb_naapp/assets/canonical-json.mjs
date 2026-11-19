// Canonical UTF-8 JSON shared by browser digest consumers. The host has
// already strictly parsed JSON; unsupported values remain refused here.
function scalarString(value) {
  for (const point of value)
    if (point.codePointAt(0) >= 0xd800 && point.codePointAt(0) <= 0xdfff)
      throw new TypeError("Unpaired surrogate");
  return JSON.stringify(value);
}
function compareKeys(left, right) {
  const a = Array.from(left, (c) => c.codePointAt(0)),
    b = Array.from(right, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
export function canonical(value) {
  if (value === null || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "string") return scalarString(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0))
      throw new TypeError("Safe integers only");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (
    value &&
    typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype
  )
    return (
      "{" +
      Object.keys(value)
        .sort(compareKeys)
        .map((key) => scalarString(key) + ":" + canonical(value[key]))
        .join(",") +
      "}"
    );
  throw new TypeError("Not JSON");
}

// B2: the same covered object and domain used by Approvals and aw.
export async function coveredRequestDigest(payload) {
  if (
    !payload ||
    Array.isArray(payload) ||
    Object.getPrototypeOf(payload) !== Object.prototype
  )
    throw new TypeError("Covered request must be an object");
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode("aweb.approval-request/1\n" + canonical(payload)),
  );
  return Array.from(new Uint8Array(bytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
