import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { IdStatusClient } from "../src/identity/id_status.js";
import { verifyIdChain, type IdChain } from "../src/identity/id_verification.js";

const v = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));
const c = v.verification_cases.find((row: any) => row.name === "delegated-child-authorized");
const chain: IdChain = { v: 1, type: "aweb.id-chain", certificates: c.chain.map((name: string) => v.certificates[name].signed) };
const parentKey = c.namespace_authority.controller_key;
const childKey = v.status_fixtures[c.status].namespace.epochs.at(-1).did_key;
const registry = "https://registry.example.test";

for (const fixture of ["delegated_child", "delegated_child_missing", "delegated_child_unsigned"]) {
  test(`production reader uses ancestor discovery and the explicit child record: ${fixture}`, async () => {
    const names: string[] = [];
    const client = new IdStatusClient(async (url, init) => {
      expect(url).toBe(`${registry}/v1/id-certificates/status`);
      expect(JSON.parse(init!.body as string).domain).toBe("tenant.aweb.ai");
      return new Response(JSON.stringify(v.status_fixtures[fixture]));
    }, async name => {
      names.push(name);
      return name === "_awid.aweb.ai" ? [[`awid=v1;controller=${parentKey};registry=${registry}`]] : [];
    });
    const evidence = await client.evidence(chain, c.subject);
    expect(evidence?.namespace_authority).toEqual(c.namespace_authority);
    expect(names).toEqual(["_awid.tenant.aweb.ai", "_awid.aweb.ai"]);
    expect(verifyIdChain(chain, c.subject, evidence).reason).toBe(fixture === "delegated_child" ? "verified" : "evidence_unavailable");
  });
}

test("no found TXT never fetches public-default status", async () => {
  let reads = 0;
  const guarded = new IdStatusClient(async () => { reads++; return new Response(JSON.stringify(v.status_fixtures[c.status])); }, async () => []);
  expect(await guarded.evidence(chain, c.subject)).toBeNull();
  expect(reads).toBe(0);
});

test("exact child TXT wins before ancestor discovery", async () => {
  const names: string[] = [];
  const client = new IdStatusClient(async () => new Response(JSON.stringify(v.status_fixtures[c.status])), async name => {
    names.push(name);
    return [[`awid=v1;controller=${childKey};registry=${registry}`]];
  });
  const evidence = await client.evidence(chain, c.subject);
  expect(names).toEqual(["_awid.tenant.aweb.ai"]);
  expect(evidence?.namespace_authority.inherited).toBe(false);
  expect(verifyIdChain(chain, c.subject, evidence)).toEqual(c.expected);
});

test("delegated evidence expires after 60s and a changed parent key cannot revive the old witness", async () => {
  let now = 100_000, reads = 0, key = parentKey;
  const client = new IdStatusClient(async () => { reads++; return new Response(JSON.stringify(v.status_fixtures[c.status])); },
    async name => name === "_awid.aweb.ai" ? [[`awid=v1;controller=${key};registry=${registry}`]] : [], () => now);
  expect(verifyIdChain(chain, c.subject, await client.evidence(chain, c.subject))).toEqual(c.expected);
  now += 60_000;
  expect((await client.evidence(chain, c.subject))?.age_seconds).toBe(60);
  expect(reads).toBe(1);
  now += 1000;
  key = childKey;
  expect(verifyIdChain(chain, c.subject, await client.evidence(chain, c.subject)).reason).toBe("evidence_unavailable");
  expect(reads).toBe(2);
});
