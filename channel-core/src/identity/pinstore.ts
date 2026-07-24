import { dirname } from "node:path";
import { mkdir, open, rename, rm } from "node:fs/promises";
import yaml from "js-yaml";

export type PinResult = "ok" | "new" | "mismatch" | "skipped";
export type IdentityScope = "global" | "local";

export interface Pin {
  address: string;
  handle: string;
  stable_id?: string;
  did_key?: string;
  first_seen: string;
  last_seen: string;
  server: string;
}

export class PinStore {
  pins: Map<string, Pin> = new Map();
  addresses: Map<string, string> = new Map();

  /** Check whether a DID matches the stored pin for a global address. */
  checkPin(address: string, did: string, identityScope: IdentityScope): PinResult {
    if (identityScope === "local") return "skipped";

    const pinnedDID = this.addresses.get(address);
    if (pinnedDID === undefined) return "new";
    if (pinnedDID === did) return "ok";
    return "mismatch";
  }

  /** Record or update a TOFU pin. */
  storePin(
    did: string,
    address: string,
    handle: string,
    server: string,
  ): void {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const existing = this.pins.get(did);

    if (existing) {
      if (existing.address !== address) {
        this.addresses.delete(existing.address);
        this.addresses.set(address, did);
        existing.address = address;
      }
      existing.last_seen = now;
      existing.handle = handle;
      existing.server = server;
      return;
    }

    this.pins.set(did, {
      address,
      handle,
      first_seen: now,
      last_seen: now,
      server,
    });
    this.addresses.set(address, did);
  }

  removeAddress(address: string): boolean {
    let removed = false;

    const pinnedDID = this.addresses.get(address);
    if (pinnedDID !== undefined) {
      this.addresses.delete(address);
      const pin = this.pins.get(pinnedDID);
      if (pin?.address === address) {
        this.pins.delete(pinnedDID);
      }
      removed = true;
    }

    for (const [pinKey, pin] of this.pins) {
      if (pin.address !== address) continue;
      this.pins.delete(pinKey);
      if (this.addresses.get(address) === pinKey) {
        this.addresses.delete(address);
      }
      removed = true;
    }

    return removed;
  }

  async save(path: string): Promise<void> {
    const data = this.toYAML();
    const dir = dirname(path);
    await mkdir(dir, { recursive: true, mode: 0o700 });

    const tmpPath = `${path}.tmp-${process.pid}-${Date.now()}`;
    // "wx" (O_CREAT|O_EXCL) refuses to open an existing path, so an
    // attacker-prepared symlink at tmpPath cannot redirect the write.
    const file = await open(tmpPath, "wx", 0o600);
    try {
      await file.writeFile(data, "utf-8");
      await file.sync();
    } catch (error) {
      await file.close().catch(() => {});
      await rm(tmpPath, { force: true }).catch(() => {});
      throw error;
    }
    await file.close();
    await rename(tmpPath, path);
  }

  /** Serialize to YAML (compatible with Go's known_agents.yaml). */
  toYAML(): string {
    const pinsObj: Record<string, Pin> = {};
    for (const [k, v] of this.pins) pinsObj[k] = v;

    const addrsObj: Record<string, string> = {};
    for (const [k, v] of this.addresses) addrsObj[k] = v;

    return yaml.dump({ pins: pinsObj, addresses: addrsObj });
  }

  /**
   * Deserialize from YAML with strict schema validation. Throws on any
   * malformed input so a corrupt trust database fails closed rather than being
   * silently replaced by an empty store. js-yaml's default load rejects
   * duplicate mapping keys and unknown/unsafe tags.
   */
  static fromYAML(content: string): PinStore {
    let data: unknown;
    try {
      // JSON_SCHEMA keeps values as plain JSON types (timestamps stay strings,
      // not Date objects) and rejects unsafe/custom YAML tags; duplicate keys
      // still throw.
      data = yaml.load(content, { schema: yaml.JSON_SCHEMA });
    } catch (error) {
      throw new Error(`pin store YAML is invalid: ${(error as Error).message}`);
    }

    const store = new PinStore();
    if (data === null || data === undefined) return store;
    if (typeof data !== "object" || Array.isArray(data)) {
      throw new Error("pin store root must be a mapping");
    }
    const root = data as Record<string, unknown>;

    if (root.pins !== undefined && root.pins !== null) {
      if (typeof root.pins !== "object" || Array.isArray(root.pins)) {
        throw new Error("pin store 'pins' must be a mapping");
      }
      for (const [key, value] of Object.entries(root.pins as Record<string, unknown>)) {
        if (!key) throw new Error("pin store has an empty pin key");
        store.pins.set(key, validatePin(key, value));
      }
    }

    if (root.addresses !== undefined && root.addresses !== null) {
      if (typeof root.addresses !== "object" || Array.isArray(root.addresses)) {
        throw new Error("pin store 'addresses' must be a mapping");
      }
      for (const [key, value] of Object.entries(root.addresses as Record<string, unknown>)) {
        if (!key) throw new Error("pin store has an empty address key");
        if (typeof value !== "string" || !value) {
          throw new Error(`pin store address '${key}' must reference a non-empty pin key`);
        }
        store.addresses.set(key, value);
      }
    }

    // Every address must resolve to a known pin, or the reverse index is
    // corrupt and identity-mismatch checks would silently misfire.
    for (const [address, pinKey] of store.addresses) {
      if (!store.pins.has(pinKey)) {
        throw new Error(`pin store address '${address}' references unknown pin`);
      }
    }

    return store;
  }
}

function validatePin(key: string, value: unknown): Pin {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`pin '${key}' must be a mapping`);
  }
  const raw = value as Record<string, unknown>;

  const requireString = (field: string): string => {
    const v = raw[field];
    if (typeof v !== "string" || v === "") {
      throw new Error(`pin '${key}' field '${field}' must be a non-empty string`);
    }
    return v;
  };
  const optionalString = (field: string): string | undefined => {
    const v = raw[field];
    if (v === undefined || v === null) return undefined;
    if (typeof v !== "string") {
      throw new Error(`pin '${key}' field '${field}' must be a string`);
    }
    return v;
  };

  const pin: Pin = {
    address: requireString("address"),
    handle: optionalString("handle") ?? "",
    first_seen: requireString("first_seen"),
    last_seen: requireString("last_seen"),
    server: optionalString("server") ?? "",
  };
  const stableId = optionalString("stable_id");
  if (stableId !== undefined) pin.stable_id = stableId;
  const didKey = optionalString("did_key");
  if (didKey !== undefined) pin.did_key = didKey;
  return pin;
}
