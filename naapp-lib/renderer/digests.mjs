import { canonical } from "../src/aweb_naapp/assets/canonical-json.mjs";
export { canonical };

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
