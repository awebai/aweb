import metadata from "../package.json" with { type: "json" };

export interface ClientMetadata {
  name: string;
  version: string;
}

export const CORE_CLIENT_METADATA: ClientMetadata = {
  name: "aweb-channel-core",
  version: metadata.version,
};

/** Unsigned diagnostics only; these headers convey no authority. */
export function clientMetadataHeaders(client: ClientMetadata = CORE_CLIENT_METADATA): Record<string, string> {
  const token = `${client.name}/${client.version}`;
  return { "User-Agent": token, "X-AWEB-Client-Version": token };
}

export function identifiedFetch(client: ClientMetadata = CORE_CLIENT_METADATA): typeof fetch {
  return (input, init) => {
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    for (const [name, value] of Object.entries(clientMetadataHeaders(client))) headers.set(name, value);
    return fetch(input, { ...init, headers });
  };
}
