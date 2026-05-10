// Local JWT verification against the install's JWKS, with cookie-mode
// fallback for browsers that hold the session in an HttpOnly cookie
// instead of a Bearer header. Mirrors `manyrows-go/auth.Middleware`.
//
// Tokens are signed ES256. The verifier fetches
// `${baseURL}/.well-known/jwks.json` once on first verify, caches the
// keys, and refetches automatically on a kid mismatch. No round trip
// per request; no shared secret on the customer side.

import { createRemoteJWKSet, customFetch, jwtVerify, type JWTVerifyGetKey } from "jose";

const USER_AGENT = "manyrows-node-auth/1.0";

const ACCESS_COOKIE_NAME = "mr_at";

export interface VerifyOptions {
  /** Base URL of the ManyRows service, e.g. "https://app.manyrows.com". */
  baseURL: string;
  /** Workspace slug. Kept on the type for forward-compat (audience checks etc.). */
  workspaceSlug: string;
  /** App ID. Kept on the type for forward-compat (audience checks etc.). */
  appId: string;
  /**
   * Optional fetch implementation override. Forwarded to the JWKS
   * fetcher; useful for tests, proxies, or environments that need to
   * customise outbound HTTP.
   */
  fetch?: typeof fetch;
}

// Cache the JWKS getter per baseURL so multiple verifyToken calls
// share one in-memory key cache and one HTTP round trip per cooldown
// window. Key is the resolved JWKS URL.
const jwksCache = new Map<string, JWTVerifyGetKey>();

function getJWKS(baseURL: string, fetchImpl?: typeof fetch): JWTVerifyGetKey {
  const url = `${baseURL.replace(/\/+$/, "")}/.well-known/jwks.json`;
  // The fetch impl is part of the cache key so a test that swaps fetch
  // gets a fresh getter (otherwise vi.stubGlobal won't take effect).
  const cacheKey = fetchImpl ? `${url}::custom` : url;
  let getter = jwksCache.get(cacheKey);
  if (!getter) {
    const opts = fetchImpl ? { [customFetch]: fetchImpl } : undefined;
    getter = createRemoteJWKSet(new URL(url), opts);
    jwksCache.set(cacheKey, getter);
  }
  return getter;
}

/**
 * Verify a user's bearer JWT against the install's JWKS.
 *
 * Returns the user ID (`sub` claim) on success.
 * Returns null if the token is empty, malformed, or fails signature /
 * expiry verification — callers should treat this as "not authenticated"
 * and 401 the request.
 *
 * Throws only on the JWKS fetch failing in a way that could mask a
 * legitimate token (network down before the cache is warm). Callers
 * in security-sensitive contexts should treat thrown errors the same
 * as `null` — fail closed.
 */
export async function verifyToken(
  token: string,
  opts: VerifyOptions,
): Promise<string | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, getJWKS(opts.baseURL, opts.fetch), {
      algorithms: ["ES256"],
      clockTolerance: 60,
    });
    const sub = payload.sub;
    return typeof sub === "string" && sub.length > 0 ? sub : null;
  } catch {
    // Signature mismatch, expired, malformed, etc. → not authenticated.
    return null;
  }
}

/**
 * Extract the bearer token from an Authorization header value (or null).
 * Case-insensitive on the "Bearer " prefix. Trims whitespace.
 */
export function bearerToken(headerValue: string | string[] | undefined): string | null {
  if (!headerValue) return null;
  const value = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (!value) return null;
  const trimmed = value.trim();
  if (trimmed.length < 7) return null;
  if (trimmed.slice(0, 7).toLowerCase() !== "bearer ") return null;
  const tok = trimmed.slice(7).trim();
  return tok.length > 0 ? tok : null;
}

/**
 * Extract the mr_at session cookie from a Cookie header value. Used as
 * a fallback when the SDK is in cookie mode and no Authorization
 * header is present. Returns null when absent / empty.
 */
export function mrAtCookie(cookieHeaderValue: string | string[] | undefined): string | null {
  if (!cookieHeaderValue) return null;
  const value = Array.isArray(cookieHeaderValue) ? cookieHeaderValue.join("; ") : cookieHeaderValue;
  if (!value) return null;
  for (const raw of value.split(";")) {
    const eq = raw.indexOf("=");
    if (eq < 0) continue;
    const name = raw.slice(0, eq).trim();
    if (name !== ACCESS_COOKIE_NAME) continue;
    const v = raw.slice(eq + 1).trim();
    return v.length > 0 ? v : null;
  }
  return null;
}

// ===== Express-style middleware =====

/**
 * Marker interface — Express request augmentation. Apps should declare:
 *
 *   declare global {
 *     namespace Express {
 *       interface Request extends AuthenticatedRequest {}
 *     }
 *   }
 *
 * to get typed access to `req.manyrowsUserId`.
 */
export interface AuthenticatedRequest {
  manyrowsUserId?: string;
}

export interface ExpressMiddlewareOptions extends VerifyOptions {
  /**
   * Optional callback fired when verification fails for any reason
   * (network error, bad token, missing user). Useful for logging/metrics.
   * The middleware always responds 401 regardless of what this returns.
   */
  onError?: (err: unknown) => void;
}

// Minimal structural types — compatible with Express, Connect, Polka, etc.
// We intentionally don't depend on `@types/express` to keep the SDK's
// install footprint small.
interface ReqLike {
  headers: Record<string, string | string[] | undefined>;
}
interface ResLike {
  status: (code: number) => ResLike;
  send: (body: string) => unknown;
}
type NextFn = (err?: unknown) => void;

/**
 * Express-style middleware. On success, sets `req.manyrowsUserId` and calls
 * `next()`. On any failure, responds with 401 Unauthorized.
 *
 * Token resolution order:
 *   1. Authorization: Bearer <jwt>   (Tier 1 / local mode)
 *   2. Cookie: mr_at=<jwt>           (cookie mode — same-host /
 *                                     custom-domain CNAME deploys)
 *
 * Example:
 *
 *   app.use(expressMiddleware({
 *     baseURL: 'https://app.manyrows.com',
 *     workspaceSlug: 'acme',
 *     appId: 'app_xxx',
 *   }));
 */
export function expressMiddleware(opts: ExpressMiddlewareOptions) {
  return async (req: ReqLike & AuthenticatedRequest, res: ResLike, next: NextFn): Promise<void> => {
    const token =
      bearerToken(req.headers["authorization"] ?? req.headers["Authorization"]) ??
      mrAtCookie(req.headers["cookie"] ?? req.headers["Cookie"]);
    if (!token) {
      res.status(401).send("Unauthorized");
      return;
    }
    try {
      const userId = await verifyToken(token, opts);
      if (!userId) {
        res.status(401).send("Unauthorized");
        return;
      }
      req.manyrowsUserId = userId;
      next();
    } catch (err) {
      opts.onError?.(err);
      res.status(401).send("Unauthorized");
    }
  };
}

// User-agent string is currently unused (the JWKS fetch goes through
// jose, which sets its own UA). Keeping the constant exported via the
// build for parity with the other SDK shapes if a customer wants to
// label outbound traffic.
export const __USER_AGENT = USER_AGENT;
