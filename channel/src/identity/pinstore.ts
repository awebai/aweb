import yaml from "js-yaml";

export type PinResult = "ok" | "new" | "mismatch" | "skipped";

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

  /** Check whether a DID matches the stored pin for an address. */
  checkPin(address: string, did: string, lifetime: string): PinResult {
    if (lifetime === "ephemeral") return "skipped";

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

  /** Serialize to YAML (compatible with Go's known_agents.yaml). */
  toYAML(): string {
    const pinsObj: Record<string, Pin> = {};
    for (const [k, v] of this.pins) pinsObj[k] = v;

    const addrsObj: Record<string, string> = {};
    for (const [k, v] of this.addresses) addrsObj[k] = v;

    return yaml.dump({ pins: pinsObj, addresses: addrsObj });
  }

  /** Deserialize from YAML. */
  static fromYAML(content: string): PinStore {
    const data = yaml.load(content) as {
      pins?: Record<string, Pin>;
      addresses?: Record<string, string>;
    } | null;

    const store = new PinStore();
    if (!data) return store;

    if (data.pins) {
      for (const [k, v] of Object.entries(data.pins)) {
        store.pins.set(k, v);
      }
    }
    if (data.addresses) {
      for (const [k, v] of Object.entries(data.addresses)) {
        store.addresses.set(k, v);
      }
    }
    return store;
  }
}
