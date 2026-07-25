export const MAX_HTTP_RESPONSE_BYTES = 10 * 1024 * 1024;
export const MAX_HTTP_ERROR_BYTES = 64 * 1024;

export async function readBoundedResponse(
  response: Response,
  maxBytes: number = MAX_HTTP_RESPONSE_BYTES,
): Promise<string> {
  const declaredLength = Number(response.headers.get("Content-Length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await response.body?.cancel().catch(() => {});
    throw new Error(`HTTP response exceeds maximum size of ${maxBytes} bytes`);
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error(`HTTP response exceeds maximum size of ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(body);
}

export async function readBoundedJSON<T>(response: Response): Promise<T> {
  return JSON.parse(await readBoundedResponse(response)) as T;
}
