import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test, vi } from "vitest";
import { serverEndpoints } from "./helpers/server_endpoints.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const project = "aweb-candidate-08f4f622d1ec-780cad-naapp-library";

// The gate's naming rule, asked independently of the helper.
function gateHostname(service: string): string {
  return execFileSync("python3", [join(repoRoot, "scripts/candidate-network.py"), "hostname", project, service],
    { encoding: "utf8" }).trim();
}

describe("serverEndpoints", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test("inside a candidate runner it reaches both services by gate hostname and reserves no port", async () => {
    vi.stubEnv("CANDIDATE_RUNNER_NAME", "probe");
    vi.stubEnv("AWEB_DOCKER_PUBLISHED_HOST", "aweb-docker.test");
    const reserve = vi.fn(async (): Promise<number[]> => {
      throw new Error("unexpected host allocation");
    });
    const endpoints = await serverEndpoints(repoRoot, project, reserve);
    expect(reserve).not.toHaveBeenCalled();
    expect([endpoints.awebURL, endpoints.awidURL]).toEqual([
      `http://${gateHostname("aweb")}:8000`,
      `http://${gateHostname("awid")}:8010`,
    ]);
    expect(gateHostname("aweb")).not.toEqual(gateHostname("awid"));
  });

  test("outside a runner it publishes on reserved loopback ports", async () => {
    vi.stubEnv("CANDIDATE_RUNNER_NAME", "");
    vi.stubEnv("AWEB_DOCKER_PUBLISHED_HOST", "aweb-docker.test");
    const endpoints = await serverEndpoints(repoRoot, project, async (count) => {
      expect(count).toBe(4);
      return [41000, 41001, 41002, 41003];
    });
    expect(endpoints).toEqual({
      awebPort: 41000, awidPort: 41001, pgPort: 41002, redisPort: 41003,
      awebURL: "http://aweb-docker.test:41000",
      awidURL: "http://aweb-docker.test:41001",
    });
  });
});
