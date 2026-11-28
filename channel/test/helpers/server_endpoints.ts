import { execFileSync } from "node:child_process";
import { join } from "node:path";

export interface ServerEndpoints {
  awebPort: number;
  awidPort: number;
  pgPort: number;
  redisPort: number;
  awebURL: string;
  awidURL: string;
}

/** The candidate gate's service hostname, from the gate's own naming rule. */
export function candidateHostname(repoRoot: string, project: string, service: string): string {
  return execFileSync("python3", [join(repoRoot, "scripts/candidate-network.py"), "hostname", project, service],
    { encoding: "utf8" }).trim();
}

export function dockerPublishedHost(): string {
  const host = process.env.AWEB_DOCKER_PUBLISHED_HOST || "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "aweb-docker.test") {
    throw new Error(`AWEB_DOCKER_PUBLISHED_HOST has unsupported fixed value ${host}`);
  }
  return host;
}

/**
 * Where the managed stack listens. Inside a candidate runner the services are
 * reached directly by their gate hostnames and no host port is reserved;
 * elsewhere they are published on reserved loopback ports.
 */
export async function serverEndpoints(
  repoRoot: string,
  projectName: string,
  reserveLoopbackPorts: (count: number) => Promise<number[]>,
): Promise<ServerEndpoints> {
  const directNetwork = Boolean(process.env.CANDIDATE_RUNNER_NAME);
  const [awebPort, awidPort, pgPort, redisPort] = directNetwork
    ? [8000, 8010, 5432, 6379] : await reserveLoopbackPorts(4);
  const publishedHost = dockerPublishedHost();
  const host = (service: string) =>
    directNetwork ? candidateHostname(repoRoot, projectName, service) : publishedHost;
  return {
    awebPort, awidPort, pgPort, redisPort,
    awebURL: `http://${host("aweb")}:${awebPort}`,
    awidURL: `http://${host("awid")}:${awidPort}`,
  };
}
