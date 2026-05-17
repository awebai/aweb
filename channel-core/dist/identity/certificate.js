import { readFile } from "node:fs/promises";
export async function loadTeamCertificate(path) {
    const content = await readFile(path, "utf-8");
    return JSON.parse(content);
}
export function encodeTeamCertificateHeader(cert) {
    return Buffer.from(JSON.stringify(cert), "utf-8").toString("base64");
}
