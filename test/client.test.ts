import { describe, it, expect, vi } from "vitest";
import { Client, ManyRowsError } from "../src/index.js";

type MockReply =
  | { body: unknown; status?: number; ok?: boolean }
  | { error: Error };

function mockFetch(replies: MockReply[]): typeof fetch {
  let i = 0;
  return vi.fn(async (url: any) => {
    const r = replies[Math.min(i++, replies.length - 1)]!;
    if ("error" in r) throw r.error;
    const status = r.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: status === 200 ? "OK" : "Error",
      url: String(url),
      text: async () => (typeof r.body === "string" ? r.body : JSON.stringify(r.body)),
      json: async () => r.body,
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

const baseOpts = {
  baseURL: "https://app.manyrows.com",
  workspaceSlug: "acme",
  appId: "app_123",
  apiKey: "mr_test_key",
};

describe("Client constructor", () => {
  it("throws if a required option is missing", () => {
    expect(() => new Client({ ...baseOpts, baseURL: "" })).toThrow(/baseURL/);
    expect(() => new Client({ ...baseOpts, workspaceSlug: "" })).toThrow(/workspaceSlug/);
    expect(() => new Client({ ...baseOpts, appId: "" })).toThrow(/appId/);
    expect(() => new Client({ ...baseOpts, apiKey: "" })).toThrow(/apiKey/);
  });

  it("strips trailing slashes from baseURL", async () => {
    const fetchMock = mockFetch([{ body: { workspaceId: "ws", projectId: "p", appId: "app_123", updatedAt: "x", config: { public: [], private: [], secrets: [] }, flags: { client: [], server: [] } } }]);
    const client = new Client({ ...baseOpts, baseURL: "https://app.manyrows.com///", fetch: fetchMock });
    await client.getDelivery();
    const callArg = (fetchMock as any).mock.calls[0][0] as string;
    expect(callArg).toBe("https://app.manyrows.com/x/acme/api/apps/app_123/");
    expect(callArg).not.toContain(".com//");
  });
});

describe("getDelivery", () => {
  it("returns the parsed delivery body", async () => {
    const fetchMock = mockFetch([
      {
        body: {
          workspaceId: "ws_1",
          projectId: "p_1",
          appId: "app_123",
          updatedAt: "2026-01-15T10:30:00Z",
          config: { public: [{ key: "theme", type: "string", value: "dark" }], private: [], secrets: [] },
          flags: { client: [], server: [{ key: "beta", enabled: true }] },
        },
      },
    ]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    const d = await client.getDelivery();
    expect(d.workspaceId).toBe("ws_1");
    expect(d.config.public[0]).toEqual({ key: "theme", type: "string", value: "dark" });
    expect(d.flags.server[0]?.enabled).toBe(true);
  });

  it("sends X-API-Key and User-Agent headers", async () => {
    const fetchMock = mockFetch([{ body: { workspaceId: "ws", projectId: "p", appId: "app_123", updatedAt: "", config: { public: [], private: [], secrets: [] }, flags: { client: [], server: [] } } }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    await client.getDelivery();
    const init = (fetchMock as any).mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["X-API-Key"]).toBe("mr_test_key");
    expect(headers["User-Agent"]).toMatch(/^manyrows-node\//);
  });
});

describe("error handling", () => {
  it("throws ManyRowsError with status + body on non-2xx", async () => {
    const fetchMock = mockFetch([{ status: 401, body: "invalid api key" }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    await expect(client.getDelivery()).rejects.toThrow(ManyRowsError);
    try {
      await client.getDelivery();
    } catch (err) {
      expect(err).toBeInstanceOf(ManyRowsError);
      const e = err as ManyRowsError;
      expect(e.status).toBe(401);
      expect(e.body).toBe("invalid api key");
    }
  });

  it("wraps network errors into ManyRowsError", async () => {
    const fetchMock = mockFetch([{ error: new Error("ECONNREFUSED") }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    await expect(client.getDelivery()).rejects.toThrow(/ECONNREFUSED/);
  });
});

describe("checkPermission / hasPermission", () => {
  it("encodes accountId and permission in query params", async () => {
    const fetchMock = mockFetch([{ body: { allowed: true, permission: "posts:edit", accountId: "u_1" } }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    const r = await client.checkPermission("u_1", "posts:edit");
    expect(r.allowed).toBe(true);
    const url = (fetchMock as any).mock.calls[0][0] as string;
    expect(url).toContain("/check-permission?");
    expect(url).toContain("accountId=u_1");
    expect(url).toMatch(/permission=posts(%3A|:)edit/);
  });

  it("hasPermission returns just the boolean", async () => {
    const fetchMock = mockFetch([{ body: { allowed: false, permission: "x", accountId: "u_1" } }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    expect(await client.hasPermission("u_1", "x")).toBe(false);
  });
});

describe("listMembers", () => {
  it("defaults page=0, pageSize=50", async () => {
    const fetchMock = mockFetch([{ body: { members: [], total: 0, page: 0, pageSize: 50 } }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    await client.listMembers();
    const url = (fetchMock as any).mock.calls[0][0] as string;
    expect(url).toContain("page=0");
    expect(url).toContain("pageSize=50");
    expect(url).not.toContain("email=");
  });

  it("passes provided page/pageSize/email", async () => {
    const fetchMock = mockFetch([{ body: { members: [], total: 0, page: 2, pageSize: 100 } }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    await client.listMembers({ page: 2, pageSize: 100, email: "alice@example.com" });
    const url = (fetchMock as any).mock.calls[0][0] as string;
    expect(url).toContain("page=2");
    expect(url).toContain("pageSize=100");
    expect(url).toContain("email=alice%40example.com");
  });

  it("listMembersByEmail forwards through listMembers", async () => {
    const fetchMock = mockFetch([{ body: { members: [], total: 0, page: 0, pageSize: 50 } }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    await client.listMembersByEmail("bob");
    const url = (fetchMock as any).mock.calls[0][0] as string;
    expect(url).toContain("email=bob");
  });
});

describe("getUser / getUserByEmail", () => {
  it("getUser hits /users?id=", async () => {
    const fetchMock = mockFetch([{ body: { user: { id: "u_1", email: "a@b.com", enabled: true, source: "registered" }, roles: [], permissions: [], fields: [] } }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    const r = await client.getUser("u_1");
    expect(r.user.id).toBe("u_1");
    const url = (fetchMock as any).mock.calls[0][0] as string;
    expect(url).toContain("/users?id=u_1");
  });

  it("getUserByEmail hits /users?email=", async () => {
    const fetchMock = mockFetch([{ body: { user: { id: "u_1", email: "a@b.com", enabled: true, source: "registered" }, roles: [], permissions: [], fields: [] } }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    await client.getUserByEmail("a@b.com");
    const url = (fetchMock as any).mock.calls[0][0] as string;
    expect(url).toContain("/users?email=a%40b.com");
  });
});

describe("listUserFields", () => {
  it("returns the userFields array", async () => {
    const fetchMock = mockFetch([{
      body: {
        userFields: [
          { id: "f_1", key: "name", valueType: "string", label: "Name", status: "active" },
          { id: "f_2", key: "verified", valueType: "bool", status: "active" },
        ],
      },
    }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    const fields = await client.listUserFields();
    expect(fields).toHaveLength(2);
    expect(fields[0]?.key).toBe("name");
  });

  it("returns [] when userFields is missing", async () => {
    const fetchMock = mockFetch([{ body: {} }]);
    const client = new Client({ ...baseOpts, fetch: fetchMock });
    expect(await client.listUserFields()).toEqual([]);
  });
});
