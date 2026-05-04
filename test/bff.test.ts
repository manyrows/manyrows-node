import { describe, it, expect, vi } from "vitest";
import {
  BffClient,
  BffError,
  PublicProxy,
  OAuthCallbackHtml,
  appendQuery,
} from "../src/index.js";

type MockReply = { body: unknown; status?: number; contentType?: string } | { error: Error };

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
      headers: new Headers(r.contentType ? { "content-type": r.contentType } : {}),
      text: async () => (typeof r.body === "string" ? r.body : JSON.stringify(r.body)),
      json: async () => r.body,
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

const BASE = "https://app.manyrows.com";
const CID = "client_abc";
const CSECRET = "secret_xyz";
const EXPECTED_BASIC = "Basic " + Buffer.from(`${CID}:${CSECRET}`, "utf8").toString("base64");

function newBff(fetchImpl: typeof fetch): BffClient {
  return new BffClient({ baseURL: BASE, clientId: CID, clientSecret: CSECRET, fetch: fetchImpl });
}

// ===== BffClient =====

describe("BffClient constructor", () => {
  it("rejects empty args", () => {
    expect(() => new BffClient({ baseURL: "", clientId: CID, clientSecret: CSECRET })).toThrow();
    expect(() => new BffClient({ baseURL: BASE, clientId: "", clientSecret: CSECRET })).toThrow();
    expect(() => new BffClient({ baseURL: BASE, clientId: CID, clientSecret: "" })).toThrow();
  });

  it("strips trailing slashes on baseURL", async () => {
    const f = mockFetch([{ body: { sessionId: "s", userId: "u", expiresAt: "x" } }]);
    const bff = new BffClient({ baseURL: BASE + "//", clientId: CID, clientSecret: CSECRET, fetch: f });
    await bff.loginPassword("a@b.com", "pw", false, {});
    const url = (f as any).mock.calls[0][0] as string;
    expect(url).toBe(BASE + "/bff/login");
  });
});

describe("BffClient.loginPassword", () => {
  it("posts /bff/login with Basic auth + forwarded headers + decodes session", async () => {
    const f = mockFetch([{ body: { sessionId: "sess_1", userId: "u_1", expiresAt: "2030-01-01T00:00:00Z" } }]);
    const s = await newBff(f).loginPassword("a@b.com", "pw", true, {
      clientIp: "1.2.3.4",
      clientUserAgent: "Mozilla",
    });

    expect(s.sessionId).toBe("sess_1");
    expect(s.userId).toBe("u_1");
    expect(s.totpRequired).toBeUndefined();

    const [url, init] = (f as any).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(BASE + "/bff/login");
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe(EXPECTED_BASIC);
    expect(headers["X-BFF-Client-IP"]).toBe("1.2.3.4");
    expect(headers["X-BFF-Client-User-Agent"]).toBe("Mozilla");
  });

  it("surfaces totpRequired branch", async () => {
    const f = mockFetch([{ body: { totpRequired: true, challengeToken: "ct_xyz" } }]);
    const s = await newBff(f).loginPassword("a@b.com", "pw", false);
    expect(s.totpRequired).toBe(true);
    expect(s.challengeToken).toBe("ct_xyz");
    expect(s.sessionId).toBeUndefined();
  });

  it("omits forwarded headers when absent", async () => {
    const f = mockFetch([{ body: { sessionId: "s", userId: "u", expiresAt: "x" } }]);
    await newBff(f).loginPassword("a@b.com", "pw", false);
    const init = (f as any).mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["X-BFF-Client-IP"]).toBeUndefined();
    expect(headers["X-BFF-Client-User-Agent"]).toBeUndefined();
  });
});

describe("BffClient.verifyOtp", () => {
  it("omits appId when null", async () => {
    const f = mockFetch([{ body: { sessionId: "s", userId: "u", expiresAt: "x" } }]);
    await newBff(f).verifyOtp("a@b.com", "123456", null, false);
    const body = (f as any).mock.calls[0][1].body as string;
    expect(body).not.toContain("appId");
  });

  it("includes appId on register flow + decodes passwordAlreadySet", async () => {
    const f = mockFetch([{ body: { sessionId: "s", userId: "u", expiresAt: "x", passwordAlreadySet: true } }]);
    const s = await newBff(f).verifyOtp("a@b.com", "123456", "app_42", true);
    expect(s.passwordAlreadySet).toBe(true);
    const body = (f as any).mock.calls[0][1].body as string;
    expect(body).toContain("app_42");
  });
});

describe("BffClient.proxy", () => {
  it("GET adds session header + Basic auth + forwards body", async () => {
    const f = mockFetch([{ body: { ok: true }, contentType: "application/json" }]);
    const r = await newBff(f).proxyGet("sess_42", "/me", {
      clientIp: "1.2.3.4",
      clientUserAgent: "Mozilla",
    });
    expect(r.status).toBe(200);
    expect(r.body).toBe('{"ok":true}');

    const [url, init] = (f as any).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(BASE + "/bff/proxy/me");
    expect((init.headers as any)["X-BFF-Session-ID"]).toBe("sess_42");
    expect((init.headers as any)["Authorization"]).toBe(EXPECTED_BASIC);
  });

  it("POST sets Content-Type when body provided", async () => {
    const f = mockFetch([{ body: { ok: true } }]);
    await newBff(f).proxyPost("sess", "/setups", '{"name":"x"}');
    const init = (f as any).mock.calls[0][1] as RequestInit;
    expect((init.headers as any)["Content-Type"]).toBe("application/json");
    expect(init.body).toBe('{"name":"x"}');
  });

  it("rejects empty session ID", async () => {
    const f = mockFetch([]);
    await expect(newBff(f).proxyGet("", "/me", {})).rejects.toThrow(/sessionId/);
  });
});

describe("BffClient.logout", () => {
  it("posts session ID to /bff/logout", async () => {
    const f = mockFetch([{ body: {} }]);
    await newBff(f).logout("sess_99");
    const [url, init] = (f as any).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(BASE + "/bff/logout");
    expect(init.body).toContain("sess_99");
  });
});

describe("BffClient errors", () => {
  it("wraps non-2xx as BffError with status + body", async () => {
    const f = mockFetch([{ status: 401, body: { error: "error.invalidCredentials" } }]);
    try {
      await newBff(f).loginPassword("a@b.com", "wrong", false);
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(BffError);
      expect((err as BffError).status).toBe(401);
      expect((err as BffError).body).toContain("invalidCredentials");
    }
  });

  it("wraps fetch network errors as BffError", async () => {
    const f = mockFetch([{ error: new Error("connection refused") }]);
    await expect(newBff(f).loginPassword("a@b.com", "pw", false)).rejects.toThrow(BffError);
  });
});

// ===== PublicProxy =====

describe("PublicProxy.appBootGet", () => {
  it("builds expected upstream URL with no Basic auth", async () => {
    const f = mockFetch([{ body: { name: "X" } }]);
    const pp = new PublicProxy({ baseURL: BASE, workspaceSlug: "acme", fetch: f });
    const r = await pp.appBootGet("app_42");
    expect(r.status).toBe(200);
    expect(r.body).toBe('{"name":"X"}');

    const [url, init] = (f as any).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(BASE + "/x/acme/apps/app_42");
    expect(init.method).toBe("GET");
    expect((init.headers as any)["Authorization"]).toBeUndefined();
  });

  it("rejects empty appId", async () => {
    const pp = new PublicProxy({ baseURL: BASE, workspaceSlug: "acme", fetch: mockFetch([]) });
    await expect(pp.appBootGet("")).rejects.toThrow();
  });
});

describe("PublicProxy.authForward", () => {
  it("posts to full suffix with query string", async () => {
    const f = mockFetch([{ body: {} }]);
    const pp = new PublicProxy({ baseURL: BASE, workspaceSlug: "acme", fetch: f });
    await pp.authForward(
      "app_42",
      "POST",
      "/microsoft/authorize",
      "openerOrigin=http%3A%2F%2Flocalhost",
      "{}",
      "application/json",
    );

    const [url, init] = (f as any).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(BASE + "/x/acme/apps/app_42/auth/microsoft/authorize?openerOrigin=http%3A%2F%2Flocalhost");
    expect(init.method).toBe("POST");
    expect((init.headers as any)["Content-Type"]).toBe("application/json");
  });

  it("supports bare /auth path for OTP send", async () => {
    const f = mockFetch([{ body: {} }]);
    const pp = new PublicProxy({ baseURL: BASE, workspaceSlug: "acme", fetch: f });
    await pp.authForward("app_42", "POST", "", null, '{"email":"a@b.com"}', "application/json");
    const url = (f as any).mock.calls[0][0] as string;
    expect(url).toBe(BASE + "/x/acme/apps/app_42/auth");
  });

  it("normalises missing leading slash on suffix", async () => {
    const f = mockFetch([{ body: {} }]);
    const pp = new PublicProxy({ baseURL: BASE, workspaceSlug: "acme", fetch: f });
    await pp.authForward("app_42", "GET", "google/authorize", null, null, null);
    const url = (f as any).mock.calls[0][0] as string;
    expect(url).toBe(BASE + "/x/acme/apps/app_42/auth/google/authorize");
  });

  it("preserves upstream non-2xx status", async () => {
    const f = mockFetch([{ status: 409, body: { error: "error.emailAlreadyRegistered" } }]);
    const pp = new PublicProxy({ baseURL: BASE, workspaceSlug: "acme", fetch: f });
    const r = await pp.authForward("app_42", "POST", "/register", null, '{"email":"a@b.com"}', "application/json");
    expect(r.status).toBe(409);
    expect(r.body).toContain("emailAlreadyRegistered");
  });
});

// ===== OAuthCallbackHtml =====

describe("OAuthCallbackHtml.success", () => {
  it("includes ok + userId, omits totpSetupRequired when false", () => {
    const html = OAuthCallbackHtml.success("u_42", false, "/");
    expect(html).toContain('"ok":true');
    expect(html).toContain('"userId":"u_42"');
    expect(html).not.toContain("totpSetupRequired");
    expect(html).toContain('redirectURL = "/"');
  });

  it("flags totpSetupRequired when true", () => {
    const html = OAuthCallbackHtml.success("u_42", true, "/welcome");
    expect(html).toContain('"totpSetupRequired":true');
  });
});

describe("OAuthCallbackHtml.totp", () => {
  it("appends challengeToken to the redirect URL", () => {
    const html = OAuthCallbackHtml.totp("ct_abc", "/login/totp", "/login?failed=1");
    expect(html).toContain('"totpRequired":true');
    expect(html).toContain('"challengeToken":"ct_abc"');
    expect(html).toContain("/login/totp?challengeToken=ct_abc");
  });

  it("falls back to error when totp URL missing", () => {
    const html = OAuthCallbackHtml.totp("ct_abc", "", "/login?failed=1");
    expect(html).toContain("totp_redirect_not_configured");
    expect(html).toContain("/login?failed=1&error=totp_redirect_not_configured");
  });
});

describe("OAuthCallbackHtml.error", () => {
  it("encodes code into query", () => {
    const html = OAuthCallbackHtml.error("exchange_failed", "/login?failed=1");
    expect(html).toContain('"error":"exchange_failed"');
    expect(html).toContain("/login?failed=1&error=exchange_failed");
  });

  it("starts a query when redirect has none", () => {
    const html = OAuthCallbackHtml.error("missing_code", "/login");
    expect(html).toContain("/login?error=missing_code");
  });

  it("renders without redirect when URL is empty", () => {
    const html = OAuthCallbackHtml.error("missing_code", "");
    expect(html).toContain('"error":"missing_code"');
    expect(html).toContain('redirectURL = ""');
  });
});

describe("OAuthCallbackHtml structure", () => {
  it("is popup-aware", () => {
    const html = OAuthCallbackHtml.success("u_42", false, "/");
    expect(html).toContain("if (window.opener)");
    expect(html).toContain("window.location.replace");
    expect(html).toContain("manyrows-oauth-callback");
    expect(html).toContain("window.close()");
  });

  it("defuses </script> injection in payload values", () => {
    const html = OAuthCallbackHtml.error("</script><script>alert(1)</script>", "/oops");
    // Only the wrapping </script> tag may appear in the source.
    const closes = (html.match(/<\/script>/g) ?? []).length;
    expect(closes).toBe(1);
  });
});

describe("appendQuery", () => {
  it("picks the right separator", () => {
    expect(appendQuery("/x", "a", "b")).toBe("/x?a=b");
    expect(appendQuery("/x?y=1", "a", "b")).toBe("/x?y=1&a=b");
  });

  it("URL-encodes value", () => {
    // encodeURIComponent uses %20 (not + like Java's URLEncoder).
    expect(appendQuery("/x", "a", "hello world")).toBe("/x?a=hello%20world");
  });
});
