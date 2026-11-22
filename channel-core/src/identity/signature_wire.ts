/** Ed25519 owner for docs/signature-primitives.md:13-24. */
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

ed.etc.sha512Sync = (...messages) => sha512(ed.etc.concatBytes(...messages));

type Ed25519Point = InstanceType<typeof ed.ExtendedPoint>;

export enum SignatureProfile {
  Message,
  IdentityCertificate,
}

export interface SigningInput {
  message: Uint8Array;
  seed: Uint8Array;
}

export interface SignatureProof {
  signature: Uint8Array;
  message: Uint8Array;
  publicKey: Uint8Array;
  profile?: SignatureProfile;
}

export function signBytes(input: SigningInput): Uint8Array {
  return ed.sign(input.message, input.seed);
}

/** Derive the public half of the signing seed without changing its wire bytes. */
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  return ed.getPublicKey(seed);
}

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  return value;
}

/** Canonical nonidentity point; malformed encodings are ordinary refusals. */
function canonicalPoint(encoded: Uint8Array): Ed25519Point | undefined {
  if (!canonicalPointEncoding(encoded)) return undefined;
  let point: Ed25519Point;
  try {
    point = ed.ExtendedPoint.fromHex(encoded, false);
  } catch {
    return undefined;
  }
  if (point.is0()) return undefined;
  return point;
}

export function primeSubgroupPoint(encoded: Uint8Array): Ed25519Point | undefined {
  const point = canonicalPoint(encoded);
  return point?.isTorsionFree() ? point : undefined;
}

/** Noncofactored Ed25519 equation. The ID profile also requires prime-order R;
 * the message profile refuses mixed-order R by its equation under prime-order A.
 * Artifact purpose and current authority remain the typed caller's decisions.
 */
export function verifyBytes(proof: SignatureProof): boolean {
  const { signature, message, publicKey, profile = SignatureProfile.Message } = proof;
  const publicPoint = primeSubgroupPoint(publicKey);
  if (!publicPoint || signature.length !== 64) return false;

  const encodedR = signature.subarray(0, 32);
  const pointR = profile === SignatureProfile.IdentityCertificate
    ? primeSubgroupPoint(encodedR)
    : canonicalPoint(encodedR);
  const scalarS = littleEndian(signature.subarray(32));
  if (!pointR || scalarS >= ed.CURVE.n) return false;

  const challenge = littleEndian(
    sha512(ed.etc.concatBytes(encodedR, publicKey, message)),
  ) % ed.CURVE.n;
  const left = scalarS === 0n ? ed.ExtendedPoint.ZERO : ed.ExtendedPoint.BASE.multiply(scalarS);
  const challengePoint = challenge === 0n ? ed.ExtendedPoint.ZERO : publicPoint.multiply(challenge);
  return left.equals(pointR.add(challengePoint));
}


/** Representation only, per RFC 8032 5.1.2-3; curve/subgroup checks are separate.
 * Both A and R reach this production predicate (docs/signature-primitives.md).
 */
export function canonicalPointEncoding(encoded: Uint8Array): boolean {
  if (encoded.length !== 32) return false;
  const coordinate = littleEndian(encoded);
  const sign = coordinate >> 255n;
  const y = coordinate & ((1n << 255n) - 1n);
  const fieldPrime = (1n << 255n) - 19n;
  return y < fieldPrime && !(sign === 1n && (y === 1n || y === fieldPrime - 1n));
}
