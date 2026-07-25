import yaml from "js-yaml";

export type PinResult = "ok" | "new" | "mismatch" | "skipped";
export type IdentityScope = "global" | "local";

type UnknownFields = Map<string, unknown>;
type RekeyPinResult =
  | { status: "rekeyed" | "unchanged"; pin: Pin }
  | { status: "missing" | "conflict" };

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

export interface PinStoreWriter {
  compareAndSet(path: string, expectedYAML: string, desiredYAML: string): Promise<void>;
}

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
  private readonly mutablePins: Map<string, Pin> = new Map();
  addresses: Map<string, string> = new Map();
  private unknownRootFields: UnknownFields = new Map();
  // Object identity binds a pin to its preserved fields, so rekeying carries
  // them without a second key-migration invariant. Pin membership stays private
  // to prevent callers from replacing the object and silently losing that state.
  private readonly unknownPinFields: WeakMap<Pin, UnknownFields> = new WeakMap();
  private persistedYAML: string;
  private commitTail: Promise<void> = Promise.resolve();
  private pendingCommits = 0;
  private undurable = false;

  constructor() {
    this.persistedYAML = this.toYAML();
  }

  get pins(): ReadonlyMap<string, Pin> {
    return this.mutablePins;
  }

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
    const existing = this.mutablePins.get(did);

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

    this.mutablePins.set(did, {
      address,
      handle,
      first_seen: now,
      last_seen: now,
      server,
    });
    this.addresses.set(address, did);
  }

  rekeyPin(currentKey: string, nextKey: string): RekeyPinResult {
    const pin = this.mutablePins.get(currentKey);
    if (!pin) return { status: "missing" };
    if (currentKey === nextKey) return { status: "unchanged", pin };
    const occupied = this.mutablePins.get(nextKey);
    if (occupied && occupied !== pin) return { status: "conflict" };

    this.mutablePins.delete(currentKey);
    this.mutablePins.set(nextKey, pin); // Preserve object identity for unknownPinFields.
    for (const [address, pinKey] of this.addresses) {
      if (pinKey === currentKey) this.addresses.set(address, nextKey);
    }
    return { status: "rekeyed", pin };
  }

  deletePin(key: string): boolean {
    const removed = this.mutablePins.delete(key);
    if (!removed) return false;
    for (const [address, pinKey] of this.addresses) {
      if (pinKey === key) this.addresses.delete(address);
    }
    return true;
  }

  removeAddress(address: string): boolean {
    let removed = false;

    const pinnedDID = this.addresses.get(address);
    if (pinnedDID !== undefined) {
      this.addresses.delete(address);
      const pin = this.mutablePins.get(pinnedDID);
      if (pin?.address === address) {
        this.deletePin(pinnedDID);
      }
      removed = true;
    }

    for (const [pinKey, pin] of this.mutablePins) {
      if (pin.address !== address) continue;
      this.deletePin(pinKey);
      if (this.addresses.get(address) === pinKey) {
        this.addresses.delete(address);
      }
      removed = true;
    }

    return removed;
  }

  removeAddresses(addresses: string[]): boolean {
    let removed = false;
    for (const address of addresses) {
      if (address) removed = this.removeAddress(address) || removed;
    }
    return removed;
  }

  bindStableIdentity(currentKey: string, stableID: string): RekeyPinResult {
    const rekey = this.rekeyPin(currentKey, stableID);
    if ("pin" in rekey) rekey.pin.stable_id = stableID;
    return rekey;
  }

  recordVerifiedIdentity(
    pinKey: string,
    address: string,
    stableID?: string,
    didKey?: string,
  ): void {
    this.storePin(pinKey, address, "", "");
    if (!stableID) return;
    const pin = this.mutablePins.get(pinKey)!;
    pin.stable_id = stableID;
    if (didKey) pin.did_key = didKey;
  }

  replaceVerifiedIdentity(
    previousPinKey: string,
    pinKey: string,
    address: string,
    stableID?: string,
    didKey?: string,
  ): void {
    if (previousPinKey) this.deletePin(previousPinKey);
    this.recordVerifiedIdentity(pinKey, address, stableID, didKey);
  }

  advanceLogCheckpoint(stableID: string, seq: number, entryHash: string): boolean {
    const pin = this.mutablePins.get(stableID);
    if (!pin || seq <= (pin.log_seq ?? 0)) return false;
    pin.log_seq = seq;
    pin.log_entry_hash = entryHash;
    return true;
  }

  /**
   * Submit this process's desired snapshot with the exact semantic baseline it
   * read. aw reloads and checks that precondition while holding the shared file
   * lock. Concurrent commits are queued so each successful desired snapshot
   * becomes the next precondition.
   */
  async commit(writer: PinStoreWriter, path: string): Promise<void> {
    this.pendingCommits += 1;
    const attempt = this.commitTail.then(async () => {
      try {
        const desiredYAML = this.toYAML();
        await writer.compareAndSet(path, this.persistedYAML, desiredYAML);
        this.persistedYAML = desiredYAML;
        if (this.pendingCommits === 1) this.undurable = false;
      } catch (error) {
        this.undurable = true;
        throw error;
      } finally {
        this.pendingCommits -= 1;
      }
    });
    this.commitTail = attempt.catch(() => {});
    return attempt;
  }

  hasUndurableChanges(): boolean {
    return this.undurable || this.pendingCommits > 0;
  }

  /** Serialize to YAML (compatible with Go's known_agents.yaml). */
  toYAML(): string {
    const pinsObj = emptyRecord();
    for (const [key, pin] of this.mutablePins) {
      const pinObj = recordFromUnknown(this.unknownPinFields.get(pin));
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
        const pin = validatePin(key, value);
        store.mutablePins.set(key, pin);
        const unknown = collectUnknownFields(value as Record<string, unknown>, PIN_FIELDS);
        if (unknown.size > 0) store.unknownPinFields.set(pin, unknown);
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
      if (!store.mutablePins.has(pinKey)) {
        throw new Error(`pin store address '${address}' references unknown pin`);
      }
    }

    store.persistedYAML = store.toYAML();
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
