import { dirname } from "node:path";
import { mkdir, open, rename, rm } from "node:fs/promises";
import yaml from "js-yaml";

export type PinResult = "ok" | "new" | "mismatch" | "skipped";
export type IdentityScope = "global" | "local";

type UnknownFields = Map<string, unknown>;

const ROOT_FIELDS = new Set(["pins", "addresses"]);
const PIN_FIELDS = new Set([
  "address",
  "handle",
  "stable_id",
  "did_key",
  "log_seq",
  "log_entry_hash",
  "first_seen",
  "last_seen",
  "server",
]);

export interface Pin {
  address: string;
  handle: string;
  stable_id?: string;
  did_key?: string;
  /**
   * The anti-rollback checkpoint: the highest DID-log sequence verified for this
   * identity and that entry's hash. Persisted with the pin so a restart cannot
   * forget what was already verified; a served log that is behind them, or that
   * does not contain this entry, is refused (default-aajc.8).
   */
  log_seq?: number;
  log_entry_hash?: string;
  first_seen: string;
  last_seen: string;
  server: string;
}

export class PinStore {
  pins: Map<string, Pin> = new Map();
  addresses: Map<string, string> = new Map();
  private unknownRootFields: UnknownFields = new Map();
  private unknownPinFields: Map<string, UnknownFields> = new Map();

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
        this.unknownPinFields.delete(pinnedDID);
      }
      removed = true;
    }

    for (const [pinKey, pin] of this.pins) {
      if (pin.address !== address) continue;
      this.pins.delete(pinKey);
      this.unknownPinFields.delete(pinKey);
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
    const pinsObj = emptyRecord();
    for (const [key, pin] of this.pins) {
      const pinObj = recordFromUnknown(this.unknownPinFields.get(key));
      pinObj.address = pin.address;
      pinObj.handle = pin.handle;
      if (pin.stable_id !== undefined) pinObj.stable_id = pin.stable_id;
      if (pin.did_key !== undefined) pinObj.did_key = pin.did_key;
      if (pin.log_seq !== undefined) pinObj.log_seq = pin.log_seq;
      if (pin.log_entry_hash !== undefined) pinObj.log_entry_hash = pin.log_entry_hash;
      pinObj.first_seen = pin.first_seen;
      pinObj.last_seen = pin.last_seen;
      pinObj.server = pin.server;
      pinsObj[key] = pinObj;
    }

    const addressesObj = emptyRecord();
    for (const [key, value] of this.addresses) addressesObj[key] = value;

    const root = recordFromUnknown(this.unknownRootFields);
    root.pins = pinsObj;
    root.addresses = addressesObj;
    return yaml.dump(root);
  }

  /**
   * Deserialize from YAML with strict schema validation. Throws on any
   * malformed input so a corrupt trust database fails closed rather than being
   * silently replaced by an empty store. js-yaml's default load rejects
   * duplicate mapping keys and unknown/unsafe tags.
   */
  static fromYAML(content: string): PinStore {
    let data: unknown;
    let hasAnchor = false;
    try {
      // JSON_SCHEMA keeps values as plain JSON types (timestamps stay strings,
      // not Date objects) and rejects unsafe/custom YAML tags; duplicate keys
      // still throw. Anchors are detected from parser events so quoted scalar
      // text containing '&' is not confused with YAML graph syntax.
      data = yaml.load(content, {
        schema: yaml.JSON_SCHEMA,
        listener(eventType, state) {
          if (eventType === "close" && (state as unknown as { anchor?: string | null }).anchor) {
            hasAnchor = true;
          }
        },
      });
    } catch (error) {
      // Report the reason and location only; js-yaml's message embeds a snippet
      // of the offending file lines, which we do not want to surface.
      const ex = error as { reason?: string; mark?: { line?: number; column?: number } };
      const where = ex.mark ? ` at line ${(ex.mark.line ?? 0) + 1} column ${(ex.mark.column ?? 0) + 1}` : "";
      throw new Error(`pin store YAML is invalid${where}: ${ex.reason ?? "parse error"}`);
    }

    if (hasAnchor) {
      throw new Error("pin store YAML must not use anchors or aliases");
    }

    const store = new PinStore();
    // An absent file becomes an empty store in loadPinStore; a present file that
    // yields no document (empty, whitespace, comments, or a bare null) is
    // truncation/corruption, since the serializer always emits a mapping. An
    // intentional empty store is written as "{}".
    if (data === null || data === undefined) {
      throw new Error("pin store is empty or has no document (truncated?); an intentional empty store is '{}'");
    }
    if (typeof data !== "object" || Array.isArray(data)) {
      throw new Error("pin store root must be a mapping");
    }
    const root = data as Record<string, unknown>;
    rejectMergeKeys(root);
    store.unknownRootFields = collectUnknownFields(root, ROOT_FIELDS);

    if (root.pins !== undefined && root.pins !== null) {
      if (typeof root.pins !== "object" || Array.isArray(root.pins)) {
        throw new Error("pin store 'pins' must be a mapping");
      }
      for (const [key, value] of Object.entries(root.pins as Record<string, unknown>)) {
        if (!key) throw new Error("pin store has an empty pin key");
        store.pins.set(key, validatePin(key, value));
        const unknown = collectUnknownFields(value as Record<string, unknown>, PIN_FIELDS);
        if (unknown.size > 0) store.unknownPinFields.set(key, unknown);
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

function emptyRecord(): Record<string, unknown> {
  return Object.create(null) as Record<string, unknown>;
}

function recordFromUnknown(fields: UnknownFields | undefined): Record<string, unknown> {
  const record = emptyRecord();
  for (const [key, value] of fields ?? []) record[key] = value;
  return record;
}

function collectUnknownFields(
  source: Record<string, unknown>,
  knownFields: ReadonlySet<string>,
): UnknownFields {
  const unknown: UnknownFields = new Map();
  for (const [key, value] of Object.entries(source)) {
    if (!knownFields.has(key)) unknown.set(key, value);
  }
  return unknown;
}

function rejectMergeKeys(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) rejectMergeKeys(item);
    return;
  }
  if (typeof value !== "object" || value === null) return;

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (key === "<<") {
      throw new Error("pin store YAML must not use merge keys");
    }
    rejectMergeKeys(child);
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
  const logSeq = raw["log_seq"];
  if (logSeq !== undefined && logSeq !== null) {
    if (typeof logSeq !== "number" || !Number.isInteger(logSeq) || logSeq < 1) {
      throw new Error(`pin '${key}' field 'log_seq' must be a positive integer`);
    }
    pin.log_seq = logSeq;
  }
  const logEntryHash = optionalString("log_entry_hash");
  if (logEntryHash !== undefined) pin.log_entry_hash = logEntryHash;
  return pin;
}
