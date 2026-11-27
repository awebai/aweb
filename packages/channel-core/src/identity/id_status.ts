import * as dns from "node:dns/promises";
import { readBoundedJSON } from "../api/response.js";
import { canonicalJSONValue } from "./canonical.js";
import { isRecord, keyResponseIdTree, type IdChain } from "./id_certificates.js";
import { idStatusRequest, type IdStatusEvidence, type IdSubject } from "./id_verification.js";
import { discoverAuthoritativeRegistry, type ResolveTxt } from "./registry.js";

/** Production status reader: one coherent DNS/status observation, fresh through 60s. */
export class IdStatusClient {
  private cache = new Map<string, { at: number; evidence: IdStatusEvidence }>();
  private inflight = new Map<string, Promise<IdStatusEvidence | null>>();
  private enrollment = new Map<string, { at: number; value: { state: string; domain: string | null } }>();
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly resolveTxt: ResolveTxt = dns.resolveTxt,
    private readonly now: () => number = Date.now,
  ) {}

  async enrollmentFor(id: string, address: string): Promise<{ state: string; domain: string | null }> {
    const domain = address.includes("/") ? address.split("/")[0] : "";
    if (!domain) return { state: "unknown", domain: null };
    const key = `${domain}/${id}`;
    const cached = this.enrollment.get(key);
    if (cached && this.fresh(cached.at)) return cached.value;
    try {
      const value = await this.bounded(async signal => {
        const authority = await discoverAuthoritativeRegistry(domain, this.resolveTxt);
        const response = await this.fetchImpl(`${authority.registryURL}/v1/did/${encodeURIComponent(id)}/key`, { redirect: "error", signal });
        if (!response.ok && response.status !== 404) throw Error("identity enrollment unavailable");
        return keyResponseIdTree(await readBoundedJSON(response));
      });
      this.trim(this.enrollment);
      this.enrollment.set(key, { at: this.now(), value });
      return value;
    } catch { return { state: "unknown", domain: null }; }
  }

  async evidence(chain: IdChain | null, subject: IdSubject, domain?: string): Promise<IdStatusEvidence | null> {
    const plan = idStatusRequest(chain, subject, domain);
    if (plan.lookup !== "status") return null;
    const key = canonicalJSONValue(plan.request, "invalid status request");
    const cached = this.cache.get(key);
    if (cached && this.fresh(cached.at)) return { ...cached.evidence, age_seconds: (this.now() - cached.at) / 1000 };
    const pending = this.inflight.get(key);
    if (pending) return pending;
    const attempt = this.refresh(key, plan.request);
    this.inflight.set(key, attempt);
    try { return await attempt; }
    finally { this.inflight.delete(key); }
  }

  private fresh(at: number): boolean { const age = this.now() - at; return age >= 0 && age <= 60_000; }
  private trim<T>(cache: Map<string, T>): void {
    if (cache.size >= 256) cache.delete(cache.keys().next().value!);
  }
  private async refresh(key: string, request: { domain: string }): Promise<IdStatusEvidence | null> {
    this.cache.delete(key);
    try {
      const evidence = await this.bounded(async signal => {
        const authority = await discoverAuthoritativeRegistry(request.domain, this.resolveTxt);
        if (!authority.controllerDid) throw Error("identity namespace authority unavailable");
        const response = await this.fetchImpl(`${authority.registryURL}/v1/id-certificates/status`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request), redirect: "error", signal,
        });
        if (!response.ok) throw Error("identity status unavailable");
        const status = await readBoundedJSON(response);
        if (!isRecord(status)) throw Error("malformed identity status");
        return { status, namespace_authority: { domain: request.domain, dns_name: authority.dnsName, inherited: authority.inherited, controller_key: authority.controllerDid }, age_seconds: 0 };
      });
      this.trim(this.cache);
      this.cache.set(key, { at: this.now(), evidence });
      return evidence;
    } catch { return null; }
  }
  private async bounded<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(Error("identity status timed out")); }, 5000); });
    try { return await Promise.race([operation(controller.signal), timeout]); }
    finally { clearTimeout(timer!); }
  }
}
