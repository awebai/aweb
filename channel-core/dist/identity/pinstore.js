import { dirname } from "node:path";
import { mkdir, open, rename, rm } from "node:fs/promises";
import yaml from "js-yaml";
export class PinStore {
    pins = new Map();
    addresses = new Map();
    /** Check whether a DID matches the stored pin for a global address. */
    checkPin(address, did, identityScope) {
        if (identityScope === "local")
            return "skipped";
        const pinnedDID = this.addresses.get(address);
        if (pinnedDID === undefined)
            return "new";
        if (pinnedDID === did)
            return "ok";
        return "mismatch";
    }
    /** Record or update a TOFU pin. */
    storePin(did, address, handle, server) {
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
    removeAddress(address) {
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
            if (pin.address !== address)
                continue;
            this.pins.delete(pinKey);
            if (this.addresses.get(address) === pinKey) {
                this.addresses.delete(address);
            }
            removed = true;
        }
        return removed;
    }
    async save(path) {
        const data = this.toYAML();
        const dir = dirname(path);
        await mkdir(dir, { recursive: true, mode: 0o700 });
        const tmpPath = `${path}.tmp-${process.pid}-${Date.now()}`;
        const file = await open(tmpPath, "w", 0o600);
        try {
            await file.writeFile(data, "utf-8");
            await file.sync();
        }
        catch (error) {
            await file.close().catch(() => { });
            await rm(tmpPath, { force: true }).catch(() => { });
            throw error;
        }
        await file.close();
        await rename(tmpPath, path);
    }
    /** Serialize to YAML (compatible with Go's known_agents.yaml). */
    toYAML() {
        const pinsObj = {};
        for (const [k, v] of this.pins)
            pinsObj[k] = v;
        const addrsObj = {};
        for (const [k, v] of this.addresses)
            addrsObj[k] = v;
        return yaml.dump({ pins: pinsObj, addresses: addrsObj });
    }
    /** Deserialize from YAML. */
    static fromYAML(content) {
        const data = yaml.load(content);
        const store = new PinStore();
        if (!data)
            return store;
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
