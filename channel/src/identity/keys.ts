import { readFile } from "node:fs/promises";

/** Load an Ed25519 private key seed from a PEM file. */
export async function loadSigningKey(path: string): Promise<Uint8Array> {
  const content = await readFile(path, "utf-8");

  const match = content.match(
    /-----BEGIN ED25519 PRIVATE KEY-----\n([\s\S]+?)\n-----END ED25519 PRIVATE KEY-----/,
  );
  if (!match) {
    throw new Error(`no ED25519 PRIVATE KEY PEM block in ${path}`);
  }

  const b64 = match[1].replace(/\s/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);

  if (bytes.length !== 32) {
    throw new Error(`invalid seed size ${bytes.length} in ${path}`);
  }

  return bytes;
}
