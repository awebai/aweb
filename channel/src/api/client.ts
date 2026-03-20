export class APIClient {
  constructor(
    private baseURL: string,
    private apiKey: string,
  ) {}

  async get<T>(path: string): Promise<T> {
    return this.request("GET", path);
  }

  async post<T>(path: string, body?: unknown): Promise<T> {
    return this.request("POST", path, body);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = this.baseURL + path;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      Accept: "application/json",
    };
    const init: RequestInit = { method, headers };

    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    const resp = await fetch(url, init);
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new APIError(resp.status, text);
    }

    return resp.json() as Promise<T>;
  }

  /** Open an SSE stream. Returns the raw Response for streaming. */
  async openSSE(path: string): Promise<Response> {
    const url = this.baseURL + path;
    const resp = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        Accept: "text/event-stream",
        "Cache-Control": "no-cache",
      },
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new APIError(resp.status, text);
    }

    return resp;
  }
}

export class APIError extends Error {
  constructor(
    public statusCode: number,
    public body: string,
  ) {
    super(body ? `aweb: http ${statusCode}: ${body}` : `aweb: http ${statusCode}`);
  }
}
