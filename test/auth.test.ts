import { describe, it, expect, vi } from "vitest";
import { verifyToken, bearerToken, expressMiddleware } from "../src/index.js";

type MockReply = { body: unknown; status?: number } | { error: Error };

function mockFetch(replies: MockReply[]): typeof fetch {
  let i = 0;
  return vi.fn(async () => {
    const r = replies[Math.min(i++, replies.length - 1)]!;
    if ("error" in r) throw r.error;
    const status = r.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: status === 200 ? "OK" : "Error",
      text: async () => (typeof r.body === "string" ? r.body : JSON.stringify(r.body)),
      json: async () => r.body,
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

const verifyOpts = {
  baseURL: "https://app.manyrows.com",
  workspaceSlug: "acme",
  appId: "app_123",
};

// ===== bearerToken =====

describe("bearerToken", () => {
  it("extracts the token after 'Bearer '", () => {
    expect(bearerToken("Bearer abc123")).toBe("abc123");
  });

  it("is case-insensitive on the prefix", () => {
    expect(bearerToken("bearer abc")).toBe("abc");
    expect(bearerToken("BEARER abc")).toBe("abc");
    expect(bearerToken("BeArEr abc")).toBe("abc");
  });

  it("trims surrounding whitespace", () => {
    expect(bearerToken("  Bearer   abc   ")).toBe("abc");
  });

  it("returns null for missing/wrong-prefix/empty input", () => {
    expect(bearerToken(undefined)).toBeNull();
    expect(bearerToken("")).toBeNull();
    expect(bearerToken("Basic xyz")).toBeNull();
    expect(bearerToken("Bearer ")).toBeNull();
    expect(bearerToken("Bearer")).toBeNull();
  });

  it("uses the first value when given an array", () => {
    expect(bearerToken(["Bearer abc", "Bearer def"])).toBe("abc");
    expect(bearerToken([])).toBeNull();
  });
});

// ===== verifyToken =====

describe("verifyToken", () => {
  it("returns the user ID on a successful 200", async () => {
    const fetchMock = mockFetch([{ body: { user: { id: "user_xyz" } } }]);
    const id = await verifyToken("tok", { ...verifyOpts, fetch: fetchMock });
    expect(id).toBe("user_xyz");
  });

  it("returns null for empty token (no network call)", async () => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const id = await verifyToken("", { ...verifyOpts, fetch: fetchMock });
    expect(id).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns null on 401 (rejected token)", async () => {
    const fetchMock = mockFetch([{ status: 401, body: "" }]);
    const id = await verifyToken("tok", { ...verifyOpts, fetch: fetchMock });
    expect(id).toBeNull();
  });

  it("returns null on 403", async () => {
    const fetchMock = mockFetch([{ status: 403, body: "" }]);
    expect(await verifyToken("tok", { ...verifyOpts, fetch: fetchMock })).toBeNull();
  });

  it("throws on 5xx (caller should fail closed)", async () => {
    const fetchMock = mockFetch([{ status: 500, body: "oops" }]);
    await expect(verifyToken("tok", { ...verifyOpts, fetch: fetchMock })).rejects.toThrow(/500/);
  });

  it("returns null when the response has no user.id", async () => {
    const fetchMock = mockFetch([{ body: { user: {} } }]);
    expect(await verifyToken("tok", { ...verifyOpts, fetch: fetchMock })).toBeNull();
  });

  it("sends Authorization: Bearer + User-Agent", async () => {
    const fetchMock = mockFetch([{ body: { user: { id: "u" } } }]);
    await verifyToken("tok123", { ...verifyOpts, fetch: fetchMock });
    const init = (fetchMock as any).mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer tok123");
    expect(headers["User-Agent"]).toMatch(/^manyrows-node-auth\//);
  });

  it("hits the right /me URL (strips trailing slash on baseURL)", async () => {
    const fetchMock = mockFetch([{ body: { user: { id: "u" } } }]);
    await verifyToken("tok", { ...verifyOpts, baseURL: "https://app.manyrows.com/", fetch: fetchMock });
    const url = (fetchMock as any).mock.calls[0][0] as string;
    expect(url).toBe("https://app.manyrows.com/x/acme/apps/app_123/a/me");
  });
});

// ===== expressMiddleware =====

function mockExpress(authHeader?: string) {
  const req: any = { headers: {} };
  if (authHeader !== undefined) req.headers.authorization = authHeader;
  let statusCode = 200;
  let sentBody = "";
  const res: any = {
    status: (c: number) => {
      statusCode = c;
      return res;
    },
    send: (b: string) => {
      sentBody = b;
    },
    get statusCode() {
      return statusCode;
    },
    get sentBody() {
      return sentBody;
    },
  };
  const next = vi.fn();
  return { req, res, next };
}

describe("expressMiddleware", () => {
  it("calls next() and sets req.manyrowsUserId on success", async () => {
    const fetchMock = mockFetch([{ body: { user: { id: "user_xyz" } } }]);
    const mw = expressMiddleware({ ...verifyOpts, fetch: fetchMock });
    const { req, res, next } = mockExpress("Bearer good-token");
    await mw(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(req.manyrowsUserId).toBe("user_xyz");
    expect(res.statusCode).toBe(200);
  });

  it("returns 401 when no Authorization header", async () => {
    const fetchMock = mockFetch([{ body: {} }]);
    const mw = expressMiddleware({ ...verifyOpts, fetch: fetchMock });
    const { req, res, next } = mockExpress();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.sentBody).toBe("Unauthorized");
  });

  it("returns 401 when /me rejects with 401", async () => {
    const fetchMock = mockFetch([{ status: 401, body: "" }]);
    const mw = expressMiddleware({ ...verifyOpts, fetch: fetchMock });
    const { req, res, next } = mockExpress("Bearer bad-token");
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it("returns 401 + calls onError when /me throws (5xx)", async () => {
    const fetchMock = mockFetch([{ status: 500, body: "oops" }]);
    const onError = vi.fn();
    const mw = expressMiddleware({ ...verifyOpts, fetch: fetchMock, onError });
    const { req, res, next } = mockExpress("Bearer tok");
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(onError).toHaveBeenCalledOnce();
  });
});
