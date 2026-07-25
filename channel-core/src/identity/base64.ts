/**
 * Strict unpadded-standard base64 decoding, matching Go's
 * base64.RawStdEncoding.DecodeString byte for byte (default-aajc.8).
 *
 * Node's Buffer.from(value, "base64") is far more lenient than Go: it accepts
 * padding, silently ignores characters outside the alphabet, and truncates
 * rather than failing. Signatures over DID-log entries and controller
 * announcements are verified in both runtimes, so a decoder that accepts input
 * the other rejects is a verifier divergence — the exact class of bug that
 * byte-identical Go/TS verification exists to prevent.
 */

const RAW_STD_BASE64 = /^[A-Za-z0-9+/]*$/;

/** Decode strictly, or throw. Padding and stray characters are rejected. */
export function decodeRawStdBase64(value: string): Uint8Array {
  if (!RAW_STD_BASE64.test(value)) {
    throw new Error("illegal base64 data: expected unpadded standard alphabet");
  }
  // A remainder of 1 cannot encode any whole byte, so Go rejects it too.
  if (value.length % 4 === 1) {
    throw new Error("illegal base64 data: truncated final quantum");
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Decode strictly, returning an empty array on malformed input for callers that
 * treat a bad signature as "does not verify" rather than an exception.
 */
export function decodeRawStdBase64OrEmpty(value: string): Uint8Array {
  try {
    return decodeRawStdBase64(value);
  } catch {
    return new Uint8Array(0);
  }
}
