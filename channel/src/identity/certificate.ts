import { readFile } from "node:fs/promises";

export interface TeamCertificate {
  version: number;
  certificate_id: string;
  team_id: string;
  team_did_key: string;
  member_did_key: string;
  member_did_aw?: string;
  member_address?: string;
  alias: string;
  lifetime: string;
  issued_at: string;
  signature: string;
}

export async function loadTeamCertificate(path: string): Promise<TeamCertificate> {
  const content = await readFile(path, "utf-8");
  return JSON.parse(content) as TeamCertificate;
}

export function encodeTeamCertificateHeader(cert: TeamCertificate): string {
  return Buffer.from(JSON.stringify(cert), "utf-8").toString("base64");
}
