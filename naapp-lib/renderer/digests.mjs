// C1 bundle framing and C2 proposal framing. JSON is already parsed by the
// host's strict validator; this also refuses values with no canonical form.
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
async function digest(prefix, value) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(prefix + "\n" + canonical(value)),
  );
  return (
    "sha256:" +
    Array.from(new Uint8Array(bytes), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("")
  );
}
export const proposalDigest = (collection, record) =>
  digest("aweb.page-proposal/1", {
    collection,
    record_id: record.id,
    value: record.value,
  });
export const bundleDigest = (items) => digest("aweb.page-bundle/1", items);
