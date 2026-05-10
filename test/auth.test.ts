import { describe, it, expect, vi, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from "jose";
import { verifyToken, bearerToken, mrAtCookie, expressMiddleware } from "../src/index.js";

// ===== Test helpers =====
//
// Each test stands up an ES256 keypair, publishes the public half via
// a mocked /.well-known/jwks.json fetch, and signs JWTs with the
// private half. Mirrors what manyrows-core does in production.

let key: Awaited<ReturnType<typeof generateKeyPair>>;
let kid: string;
let jwks: { keys: any[] };

async function setupKey() {
  key = await generateKeyPair("ES256", { extractable: true });
  const pub = await exportJWK(key.publicKey);
  kid = await calculateJwkThumbprint({ ...pub, kty: pub.kty });
  jwks = { keys: [{ ...pub, kid, alg: "ES256", use: "sig" }] };
}

beforeAll(async () => {
  await setupKey();
});

async function signToken(opts: {
  sub?: string;
  exp?: number;
  alg?: string;
} = {}): Promise<string> {
  const sub = opts.sub ?? "user_xyz";
  return await new SignJWT({})
    .setProtectedHeader({ alg: opts.alg ?? "ES256", kid })
    .setIssuedAt()
    .setSubject(sub)
    .setExpirationTime(opts.exp ?? "5m")
    .sign(key.privateKey);
}

// Mock fetch that serves the JWKS at the expected URL and 404s anything
// else. Lets us drive the JWKS lifecycle deterministically.
function jwksFetch(): typeof fetch {
  return vi.fn(async (input: any) => {
    const url = typeof input === "string" ? input : input.url;
    if (url.endsWith("/.well-known/jwks.json")) {
      return {
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => jwks,
        text: async () => JSON.stringify(jwks),
      } as unknown as Response;
    }
    return {
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({}),
      text: async () => "",
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

// ===== mrAtCookie =====

describe("mrAtCookie", () => {
  it("extracts the mr_at cookie value", () => {
    expect(mrAtCookie("mr_at=abc123")).toBe("abc123");
  });

  it("ignores other cookies and whitespace", () => {
    expect(mrAtCookie("foo=1; mr_at=abc; bar=2")).toBe("abc");
    expect(mrAtCookie("  mr_at=abc  ")).toBe("abc");
  });

  it("handles values containing '='", () => {
    expect(mrAtCookie("mr_at=eyJ.payload=xyz")).toBe("eyJ.payload=xyz");
  });

  it("returns null when absent / empty / undefined", () => {
    expect(mrAtCookie(undefined)).toBeNull();
    expect(mrAtCookie("")).toBeNull();
    expect(mrAtCookie("foo=1; bar=2")).toBeNull();
    expect(mrAtCookie("mr_at=")).toBeNull();
  });

  it("joins arrays into one cookie string", () => {
    expect(mrAtCookie(["foo=1", "mr_at=abc"])).toBe("abc");
  });
});

// ===== verifyToken =====

describe("verifyToken (local JWKS)", () => {
  it("returns the sub claim on a valid token", async () => {
    const tok = await signToken({ sub: "user_xyz" });
    const id = await verifyToken(tok, { ...verifyOpts, fetch: jwksFetch() });
    expect(id).toBe("user_xyz");
  });

  it("returns null for empty token (no JWKS fetch)", async () => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const id = await verifyToken("", { ...verifyOpts, fetch: fetchMock });
    expect(id).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns null for malformed JWT", async () => {
    const id = await verifyToken("not.a.jwt", { ...verifyOpts, fetch: jwksFetch() });
    expect(id).toBeNull();
  });

  it("returns null for an expired token", async () => {
    const tok = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setSubject("user_xyz")
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800) // 30 min ago
      .sign(key.privateKey);
    const id = await verifyToken(tok, { ...verifyOpts, fetch: jwksFetch() });
    expect(id).toBeNull();
  });

  it("returns null when the kid isn't in the JWKS", async () => {
    const otherKey = await generateKeyPair("ES256", { extractable: true });
    const tok = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "unknown-kid" })
      .setIssuedAt()
      .setSubject("user_xyz")
      .setExpirationTime("5m")
      .sign(otherKey.privateKey);
    const id = await verifyToken(tok, { ...verifyOpts, fetch: jwksFetch() });
    expect(id).toBeNull();
  });

  it("returns null when the signature is invalid", async () => {
    // Sign with a different key, claim our kid → the JWKS lookup
    // succeeds but signature verification fails.
    const otherKey = await generateKeyPair("ES256", { extractable: true });
    const tok = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid })
      .setIssuedAt()
      .setSubject("user_xyz")
      .setExpirationTime("5m")
      .sign(otherKey.privateKey);
    const id = await verifyToken(tok, { ...verifyOpts, fetch: jwksFetch() });
    expect(id).toBeNull();
  });

  it("returns null when sub is missing", async () => {
    const tok = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(key.privateKey);
    const id = await verifyToken(tok, { ...verifyOpts, fetch: jwksFetch() });
    expect(id).toBeNull();
  });
});

// ===== expressMiddleware =====

function mockExpress(headers: Record<string, string> = {}) {
  const req: any = { headers };
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
  it("calls next() and sets req.manyrowsUserId on a Bearer header", async () => {
    const tok = await signToken({ sub: "user_xyz" });
    const mw = expressMiddleware({ ...verifyOpts, fetch: jwksFetch() });
    const { req, res, next } = mockExpress({ authorization: `Bearer ${tok}` });
    await mw(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(req.manyrowsUserId).toBe("user_xyz");
    expect(res.statusCode).toBe(200);
  });

  it("falls back to the mr_at cookie when no Bearer header", async () => {
    const tok = await signToken({ sub: "user_via_cookie" });
    const mw = expressMiddleware({ ...verifyOpts, fetch: jwksFetch() });
    const { req, res, next } = mockExpress({ cookie: `mr_at=${tok}` });
    await mw(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(req.manyrowsUserId).toBe("user_via_cookie");
  });

  it("Bearer header wins over mr_at cookie when both present", async () => {
    const tokHeader = await signToken({ sub: "from_header" });
    const tokCookie = await signToken({ sub: "from_cookie" });
    const mw = expressMiddleware({ ...verifyOpts, fetch: jwksFetch() });
    const { req, res, next } = mockExpress({
      authorization: `Bearer ${tokHeader}`,
      cookie: `mr_at=${tokCookie}`,
    });
    await mw(req, res, next);
    expect(req.manyrowsUserId).toBe("from_header");
  });

  it("returns 401 when no Authorization header and no cookie", async () => {
    const mw = expressMiddleware({ ...verifyOpts, fetch: jwksFetch() });
    const { req, res, next } = mockExpress();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.sentBody).toBe("Unauthorized");
  });

  it("returns 401 on a tampered token", async () => {
    const tok = await signToken();
    const tampered = tok.slice(0, -2) + (tok.endsWith("A") ? "BB" : "AA");
    const mw = expressMiddleware({ ...verifyOpts, fetch: jwksFetch() });
    const { req, res, next } = mockExpress({ authorization: `Bearer ${tampered}` });
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });
});
