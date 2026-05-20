import { readFile } from "node:fs/promises";
export function certificateIdentityScope(cert) {
    if (cert.identity_scope === "global" || cert.identity_scope === "local")
        return cert.identity_scope;
    if (cert.lifetime === "persistent")
        return "global";
    if (cert.lifetime === "ephemeral")
        return "local";
    return "local";
}
export async function loadTeamCertificate(path) {
    const content = await readFile(path, "utf-8");
    return JSON.parse(content);
}
export function encodeTeamCertificateHeader(cert) {
    return Buffer.from(JSON.stringify(cert), "utf-8").toString("base64");
}
