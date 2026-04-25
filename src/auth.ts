// Bearer-token verification for server-side auth. Mirrors the Go SDK's
// `auth.Middleware` pattern: validate the user's JWT against the ManyRows
// /a/app/me endpoint, then attach the user ID to the request.

const USER_AGENT = "manyrows-node-auth/1.0";

interface MeResponse {
  user?: { id?: string };
}

export interface VerifyOptions {
  /** Base URL of the ManyRows service, e.g. "https://app.manyrows.com". */
  baseURL: string;
  /** Workspace slug. */
  workspaceSlug: string;
  /** App ID. */
  appId: string;
  /**
   * Optional fetch implementation override. Defaults to the global `fetch`.
   */
  fetch?: typeof fetch;
}

/**
 * Verify a user's bearer token by calling the ManyRows /a/app/me endpoint.
 *
 * Returns the user ID on success.
 * Returns null if the token is empty or rejected by ManyRows (401/403).
 * Throws on network errors or unexpected (5xx, malformed) responses.
 *
 * Callers in security-sensitive contexts should treat thrown errors the same
 * as `null` — fail closed, don't let a flaky upstream become an auth bypass.
 */
export async function verifyToken(
  token: string,
  opts: VerifyOptions,
): Promise<string | null> {
  if (!token) return null;

  const meURL = `${opts.baseURL.replace(/\/+$/, "")}/x/${opts.workspaceSlug}/apps/${opts.appId}/a/app/me`;
  const fetchImpl = opts.fetch ?? fetch;

  const res = await fetchImpl(meURL, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": USER_AGENT,
    },
  });

  if (res.status === 401 || res.status === 403) return null;
  if (!res.ok) {
    throw new Error(`manyrows: /me returned ${res.status}`);
  }

  const data = (await res.json()) as MeResponse;
  const id = data.user?.id;
  return id && id.length > 0 ? id : null;
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
    const token = bearerToken(req.headers["authorization"] ?? req.headers["Authorization"]);
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
