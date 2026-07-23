export interface APIClientAuth {
    did: string;
    stableID: string;
    signingKey: Uint8Array;
    teamID: string;
    teamCertificateHeader: string;
}
export declare class APIClient {
    private baseURL;
    private auth;
    constructor(baseURL: string, auth: APIClientAuth);
    get<T>(path: string): Promise<T>;
    getFresh<T>(path: string): Promise<T>;
    post<T>(path: string, body?: unknown): Promise<T>;
    private request;
    /** Open an SSE stream. Returns the raw Response for streaming. */
    openSSE(path: string, signal?: AbortSignal): Promise<Response>;
    private authHeaders;
    private usesIdentityMessagingAuth;
    private identityAuthHeaders;
    private teamAuthHeaders;
}
export declare class APIError extends Error {
    statusCode: number;
    body: string;
    constructor(statusCode: number, body: string);
}
