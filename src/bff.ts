// Full-BFF client for the ManyRows /bff/* server-to-server surface.
//
// Mirrors manyrows-go's bff.Client + bff.MountAppBoot + the popup-aware
// OAuth callback HTML. Node land is too framework-fragmented to ship a
// router-mount helper (Express vs. Fastify vs. Hono vs. raw http), so
// this module provides the typed HTTP calls + the popup HTML + public
// proxies — the irreducible pieces a Node backend needs to stand up
// against AppKit's bffMode. Customers wire the routes themselves.

const USER_AGENT_BFF = "manyrows-node-bff/1.0";
const USER_AGENT_PUBLIC_PROXY = "manyrows-node-public-proxy/1.0";

const HEADER_SESSION_ID = "X-BFF-Session-ID";
const HEADER_CLIENT_IP = "X-BFF-Client-IP";
const HEADER_CLIENT_UA = "X-BFF-Client-User-Agent";

/**
 * Wire shape returned by every {@link BffClient} auth call. Stash
 * `sessionId` in a browser-facing HttpOnly cookie; on every authed
 * AppKit request your handler proxies via {@link BffClient.proxy} with
 * the same `sessionId` (carried as `X-BFF-Session-ID`).
 *
 * `expiresAt` is informational — the BFF may use it to set its
 * cookie's `Max-Age` but ManyRows is the authority on session
 * lifetime; on expiry, /bff/proxy/* returns 401.
 *
 * `totpRequired` (with `challengeToken`) is set when the user has
 * TOTP enrolled — the customer's UI prompts for the code and calls
 * {@link BffClient.verifyTotp}. No session is issued on this branch.
 *
 * `totpSetupRequired` is set when `app.Require2FA` is on but the
 * user hasn't enrolled yet. The session IS issued; the customer's
 * UI should route to a TOTP setup screen.
 *
 * `passwordAlreadySet` is set on the verify-OTP path (registration
 * flow) when the verifying user already has a password configured —
 * the customer's create-account UI uses this to skip the post-verify
 * "set your password" screen instead of showing it and erroring.
 */
export interface BffSession {
  sessionId?: string;
  userId?: string;
  expiresAt?: string;
  totpRequired?: boolean;
  challengeToken?: string;
  totpSetupRequired?: boolean;
  passwordAlreadySet?: boolean;
}

export interface BffClientOptions {
  /** Base URL of the ManyRows service, e.g. "https://app.manyrows.com". */
  baseURL: string;
  /** Per-app BFF client ID from the workspace admin UI. */
  clientId: string;
  /** Per-app BFF client secret. Pair with `clientId` for HTTP Basic. */
  clientSecret: string;
  /** Optional fetch override (tests, custom dispatcher, request tracing). */
  fetch?: typeof fetch;
}

/**
 * Forwarded browser metadata. Always pass these on each call so per-IP
 * rate limits and audit logs in ManyRows attribute to the real user
 * instead of the customer backend's egress IP.
 */
export interface ClientContext {
  /** Real browser IP. Pulled from the framework's request (e.g. `req.ip`). */
  clientIp?: string | null;
  /** Real browser User-Agent. */
  clientUserAgent?: string | null;
}

/**
 * Thrown for any non-2xx response from the ManyRows BFF surface, or for
 * network/decoding failures while talking to it. Inspect `status` and
 * `body` to distinguish auth failures (401), rate limits (429),
 * server errors (5xx).
 */
export class BffError extends Error {
  status?: number;
  body?: string;

  constructor(message: string, status?: number, body?: string) {
    super(message);
    this.name = "BffError";
    this.status = status;
    this.body = body;
  }
}

/**
 * Synchronous client for the ManyRows full-BFF endpoints under `/bff/*`.
 *
 * ```ts
 * import { BffClient } from "@manyrows/manyrows-node";
 *
 * const bff = new BffClient({
 *   baseURL: "https://app.manyrows.com",
 *   clientId: process.env.MANYROWS_BFF_CLIENT_ID!,
 *   clientSecret: process.env.MANYROWS_BFF_CLIENT_SECRET!,
 * });
 *
 * // Inside your /auth/login handler:
 * const s = await bff.loginPassword(email, password, true,
 *   { clientIp: req.ip, clientUserAgent: req.headers["user-agent"] });
 * if (s.totpRequired) {
 *   res.json({ totpRequired: true, challengeToken: s.challengeToken });
 * } else {
 *   req.session.manyrowsSessionId = s.sessionId;  // your own cookie
 *   res.json({ ok: true });
 * }
 * ```
 */
export class BffClient {
  private readonly baseURL: string;
  private readonly basicAuth: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: BffClientOptions) {
    if (!opts.baseURL) throw new Error("manyrows: baseURL is required");
    if (!opts.clientId) throw new Error("manyrows: clientId is required");
    if (!opts.clientSecret) throw new Error("manyrows: clientSecret is required");

    this.baseURL = opts.baseURL.replace(/\/+$/, "");
    this.basicAuth =
      "Basic " +
      Buffer.from(`${opts.clientId}:${opts.clientSecret}`, "utf8").toString("base64");
    this.fetchImpl = opts.fetch ?? fetch;
  }

  // ===== Login flows =====

  /** Password login. */
  async loginPassword(
    email: string,
    password: string,
    rememberMe: boolean,
    ctx: ClientContext = {},
  ): Promise<BffSession> {
    return this.postSession("/bff/login", { email, password, rememberMe }, ctx);
  }

  /** Google sign-in: `credential` is the Google ID token from GSI. */
  async loginGoogle(
    credential: string,
    rememberMe: boolean,
    ctx: ClientContext = {},
  ): Promise<BffSession> {
    return this.postSession("/bff/google", { credential, rememberMe }, ctx);
  }

  /**
   * Email-OTP code verification. Used for both registration and
   * OTP-as-primary sign-in. Pass `appId` non-null to flip ManyRows
   * into register mode.
   */
  async verifyOtp(
    email: string,
    code: string,
    appId: string | null,
    rememberMe: boolean,
    ctx: ClientContext = {},
  ): Promise<BffSession> {
    const body: Record<string, unknown> = { email, code, rememberMe };
    if (appId) body.appId = appId;
    return this.postSession("/bff/verify", body, ctx);
  }

  /** Complete a TOTP step-up after `loginPassword` / `loginGoogle` returned `totpRequired`. */
  async verifyTotp(
    challengeToken: string,
    code: string,
    ctx: ClientContext = {},
  ): Promise<BffSession> {
    return this.postSession("/bff/totp/verify", { challengeToken, code }, ctx);
  }

  /**
   * Start a discoverable WebAuthn login. Returns the raw
   * `{ challengeId, publicKeyOptions }` payload — pass it through to
   * the browser unchanged for `navigator.credentials.get`.
   */
  async passkeyLoginBegin(ctx: ClientContext = {}): Promise<unknown> {
    return this.postRaw("/bff/passkey/login/begin", {}, ctx);
  }

  /** Verify the WebAuthn assertion the browser returned and land a session. */
  async passkeyLoginFinish(
    challengeId: string,
    response: unknown,
    rememberMe: boolean,
    ctx: ClientContext = {},
  ): Promise<BffSession> {
    return this.postSession(
      "/bff/passkey/login/finish",
      { challengeId, response, rememberMe },
      ctx,
    );
  }

  /**
   * Exchange a one-time auth code (from an OAuth provider redirect) for
   * a session. `redirectUri` MUST match what the OAuth flow was started
   * with — same protection as any standard OAuth code exchange.
   */
  async exchangeAuthCode(
    code: string,
    redirectUri: string,
    ctx: ClientContext = {},
  ): Promise<BffSession> {
    return this.postSession("/bff/exchange", { code, redirectUri }, ctx);
  }

  // ===== Misc =====

  /**
   * Email-OTP "forgot password" — emails the user a code if the address
   * is registered. Returns silently regardless of existence
   * (anti-enumeration).
   */
  async forgotPassword(
    email: string,
    appId: string | null,
    ctx: ClientContext = {},
  ): Promise<void> {
    const body: Record<string, unknown> = { email };
    if (appId) body.appId = appId;
    await this.postVoid("/bff/forgot-password", body, ctx);
  }

  /** Complete the email-OTP password-reset flow. */
  async resetPassword(
    email: string,
    code: string,
    newPassword: string,
    appId: string | null,
    logoutAll: boolean,
    ctx: ClientContext = {},
  ): Promise<void> {
    const body: Record<string, unknown> = { email, code, newPassword, logoutAll };
    if (appId) body.appId = appId;
    await this.postVoid("/bff/reset-password", body, ctx);
  }

  /** Revoke a session in ManyRows. Idempotent. */
  async logout(sessionId: string, ctx: ClientContext = {}): Promise<void> {
    await this.postVoid("/bff/logout", { sessionId }, ctx);
  }

  // ===== Authenticated proxy =====

  /**
   * Proxy an authenticated AppKit data call. Forwards to ManyRows
   * `/bff/proxy{pathAndQuery}` with the user's session ID + browser
   * metadata. The customer's framework wires
   * `/apps/{appId}/a/*` (or wherever it puts authed routes) to call
   * this and relay status + body + body type back to the browser.
   *
   * The returned `headers` is the full upstream Headers map; the caller
   * decides what to forward.
   */
  async proxy(
    method: string,
    sessionId: string,
    pathAndQuery: string,
    body: string | null,
    ctx: ClientContext = {},
  ): Promise<ProxyResponse> {
    if (!sessionId) throw new Error("manyrows: sessionId is required");
    const url = `${this.baseURL}/bff/proxy${pathAndQuery}`;
    const headers: Record<string, string> = {
      Authorization: this.basicAuth,
      [HEADER_SESSION_ID]: sessionId,
      "User-Agent": USER_AGENT_BFF,
    };
    if (ctx.clientIp) headers[HEADER_CLIENT_IP] = ctx.clientIp;
    if (ctx.clientUserAgent) headers[HEADER_CLIENT_UA] = ctx.clientUserAgent;
    if (body !== null) headers["Content-Type"] = "application/json";

    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method,
        headers,
        body: body === null ? undefined : body,
      });
    } catch (err) {
      throw new BffError(
        `manyrows: proxy ${method} ${pathAndQuery} failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    const text = await res.text();
    return {
      status: res.status,
      body: text,
      contentType: res.headers.get("content-type") ?? "application/json",
      headers: res.headers,
    };
  }

  /** GET shortcut — `proxy("GET", sessionId, pathAndQuery, null, ctx)`. */
  async proxyGet(
    sessionId: string,
    pathAndQuery: string,
    ctx: ClientContext = {},
  ): Promise<ProxyResponse> {
    return this.proxy("GET", sessionId, pathAndQuery, null, ctx);
  }

  /** POST shortcut. */
  async proxyPost(
    sessionId: string,
    pathAndQuery: string,
    body: string,
    ctx: ClientContext = {},
  ): Promise<ProxyResponse> {
    return this.proxy("POST", sessionId, pathAndQuery, body, ctx);
  }

  // ===== internals =====

  private async postSession(
    path: string,
    body: unknown,
    ctx: ClientContext,
  ): Promise<BffSession> {
    const res = await this.send(path, body, ctx);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new BffError(`manyrows ${path} failed: ${text}`, res.status, text);
    }
    try {
      return (await res.json()) as BffSession;
    } catch (err) {
      throw new BffError(
        `manyrows: decode session response: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  private async postRaw(
    path: string,
    body: unknown,
    ctx: ClientContext,
  ): Promise<unknown> {
    const res = await this.send(path, body, ctx);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new BffError(`manyrows ${path} failed: ${text}`, res.status, text);
    }
    return res.json();
  }

  private async postVoid(
    path: string,
    body: unknown,
    ctx: ClientContext,
  ): Promise<void> {
    const res = await this.send(path, body, ctx);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new BffError(`manyrows ${path} failed: ${text}`, res.status, text);
    }
  }

  private async send(path: string, body: unknown, ctx: ClientContext): Promise<Response> {
    const headers: Record<string, string> = {
      Authorization: this.basicAuth,
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT_BFF,
    };
    if (ctx.clientIp) headers[HEADER_CLIENT_IP] = ctx.clientIp;
    if (ctx.clientUserAgent) headers[HEADER_CLIENT_UA] = ctx.clientUserAgent;
    try {
      return await this.fetchImpl(`${this.baseURL}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
    } catch (err) {
      throw new BffError(
        `manyrows ${path} failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}

/** Raw upstream proxy response — caller decides what to forward. */
export interface ProxyResponse {
  status: number;
  body: string;
  contentType: string;
  headers: Headers;
}

// ===========================================================================
// PublicProxy — unauthenticated browser-facing surface
// ===========================================================================

export interface PublicProxyOptions {
  baseURL: string;
  workspaceSlug: string;
  fetch?: typeof fetch;
}

/**
 * Forwards the unauthenticated browser-facing surface AppKit hits in
 * bffMode. Two patterns:
 *
 * - `GET /apps/{appId}` → `/x/{workspaceSlug}/apps/{appId}` (public boot:
 *   auth methods, branding, OAuth client IDs)
 * - `GET|POST /apps/{appId}/auth/*` → pre-login auth surface (OAuth
 *   authorize, OTP request, etc.)
 *
 * Conceptually distinct from {@link BffClient}: that calls authenticated
 * server-to-server endpoints with HTTP Basic; this just relays browser
 * requests with no credentials. The Go SDK's `MountAppBoot` does both
 * inside one router-mount helper; Node land has no portable equivalent
 * so the customer's framework wires the routes manually and calls into
 * this class.
 */
export class PublicProxy {
  private readonly baseURL: string;
  private readonly workspaceSlug: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: PublicProxyOptions) {
    if (!opts.baseURL) throw new Error("manyrows: baseURL is required");
    if (!opts.workspaceSlug) throw new Error("manyrows: workspaceSlug is required");
    this.baseURL = opts.baseURL.replace(/\/+$/, "");
    this.workspaceSlug = opts.workspaceSlug;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /** GET /x/{workspaceSlug}/apps/{appId}. AppKit's bootstrap fetch. */
  async appBootGet(appId: string): Promise<ProxyResponse> {
    if (!appId) throw new Error("manyrows: appId is required");
    return this.forward(
      "GET",
      `${this.baseURL}/x/${this.workspaceSlug}/apps/${appId}`,
      null,
      null,
    );
  }

  /**
   * Forward an `/apps/{appId}/auth/*` request to ManyRows.
   *
   * @param suffix Path segment after `/apps/{appId}/auth` — for the bare
   *   `/apps/{appId}/auth` (the OTP send endpoint) pass `""` or `"/"`;
   *   for `/apps/{appId}/auth/microsoft/authorize` pass
   *   `"/microsoft/authorize"`. Missing leading slash gets normalised.
   */
  async authForward(
    appId: string,
    method: string,
    suffix: string,
    query: string | null,
    body: string | null,
    contentType: string | null,
  ): Promise<ProxyResponse> {
    if (!appId) throw new Error("manyrows: appId is required");
    if (!method) throw new Error("manyrows: method is required");
    let s = suffix ?? "";
    if (s !== "" && !s.startsWith("/")) s = "/" + s;
    let url = `${this.baseURL}/x/${this.workspaceSlug}/apps/${appId}/auth${s}`;
    if (query) url += `?${query}`;
    return this.forward(method, url, body, contentType);
  }

  private async forward(
    method: string,
    url: string,
    body: string | null,
    contentType: string | null,
  ): Promise<ProxyResponse> {
    const headers: Record<string, string> = { "User-Agent": USER_AGENT_PUBLIC_PROXY };
    if (body !== null && contentType) headers["Content-Type"] = contentType;
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method,
        headers,
        body: body === null ? undefined : body,
      });
    } catch (err) {
      throw new BffError(
        `manyrows: public proxy ${method} ${url} failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    const text = await res.text();
    return {
      status: res.status,
      body: text,
      contentType: res.headers.get("content-type") ?? "application/json",
      headers: res.headers,
    };
  }
}

// ===========================================================================
// OAuthCallbackHtml — popup-aware /auth/oauth/callback page
// ===========================================================================

/**
 * Builds the popup-aware HTML page that the customer's
 * `/auth/oauth/callback` handler writes to the browser after
 * {@link BffClient.exchangeAuthCode} (or one of the totp/error
 * branches).
 *
 * Inline JS branches on `window.opener` at runtime: if the callback ran
 * inside a popup opened by AppKit, it postMessages a
 * `manyrows-oauth-callback` payload to the opener (which AppKit's
 * listener decodes to complete login) and closes itself. If there's no
 * opener — full-page redirect mode — the script navigates the current
 * tab to the configured success / totp / error URL instead.
 *
 * The Set-Cookie that {@link BffClient.exchangeAuthCode} caused you to
 * land on the response stays on this same response, so the opener finds
 * the session valid the moment it acts on the postMessage.
 */
export const OAuthCallbackHtml = {
  /** Successful login outcome. */
  success(userId: string | undefined, totpSetupRequired: boolean, redirectSuccessUrl: string): string {
    const payload: Record<string, unknown> = { ok: true };
    if (userId) payload.userId = userId;
    if (totpSetupRequired) payload.totpSetupRequired = true;
    return render(200, payload, redirectSuccessUrl);
  },

  /**
   * TOTP-required outcome. Falls back to the error redirect (with
   * `?error=totp_redirect_not_configured`) when `redirectTotpUrl` is
   * empty.
   */
  totp(challengeToken: string, redirectTotpUrl: string, redirectErrorUrl: string): string {
    if (!redirectTotpUrl) return this.error("totp_redirect_not_configured", redirectErrorUrl);
    return render(
      200,
      { totpRequired: true, challengeToken },
      appendQuery(redirectTotpUrl, "challengeToken", challengeToken),
    );
  },

  /** Error outcome. */
  error(errorCode: string, redirectErrorUrl: string): string {
    return render(
      400,
      { error: errorCode },
      redirectErrorUrl ? appendQuery(redirectErrorUrl, "error", errorCode) : null,
    );
  },
};

function render(status: number, payload: Record<string, unknown>, redirectUrl: string | null): string {
  // Defuse </script> injection: an error code or other field whose
  // value contains </script> would terminate our inline <script>
  // block. Replace </ with <\/ — valid JSON (the / can be escaped),
  // safe in HTML (no </script> sequence in the source).
  const payloadJson = JSON.stringify(payload).replace(/<\//g, "<\\/");
  const redirectJs = redirectUrl == null ? '""' : jsString(redirectUrl);
  const fallbackText = htmlEscape(payloadJson);

  // Mirrors manyrows-go bff/popup.go writeOAuthCallbackResult.
  return `<!DOCTYPE html>
<html>
<head><title>Completing sign-in…</title></head>
<body>
<p>Completing sign-in…</p>
<script>
(function() {
  var status = ${status};
  var payload = ${payloadJson};
  var redirectURL = ${redirectJs};
  if (window.opener) {
    try {
      window.opener.postMessage(
        { type: "manyrows-oauth-callback", status: status, payload: payload },
        window.location.origin
      );
    } catch (e) { /* opener may be closed */ }
    window.close();
    return;
  }
  if (redirectURL) {
    window.location.replace(redirectURL);
    return;
  }
  document.body.innerHTML = "<pre>" + ${jsString(fallbackText)} + "</pre>";
})();
</script>
</body>
</html>`;
}

/** Append `key=value` to `base`, picking `?` or `&` as the separator. */
export function appendQuery(base: string, key: string, value: string): string {
  if (!base) return base;
  const sep = base.indexOf("?") >= 0 ? "&" : "?";
  return `${base}${sep}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
}

/**
 * Build a JS string literal. Escapes only what's actually dangerous
 * inside an inline <script> block: the standard JSON-string set plus
 * < (for </script> safety) and U+2028 / U+2029 (which are line
 * terminators in JS, unlike in JSON, and would break a single-line
 * string). & and > are safe inside <script> — the HTML parser doesn't
 * process entities there, and only < starts a tag close.
 */
function jsString(raw: string): string {
  let out = '"';
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    switch (c) {
      case 0x22: out += "\\\""; break; // "
      case 0x5c: out += "\\\\"; break; // \
      case 0x0a: out += "\\n"; break;
      case 0x0d: out += "\\r"; break;
      case 0x09: out += "\\t"; break;
      case 0x3c: out += "\\u003c"; break; // <
      case 0x2028: out += "\\u2028"; break;
      case 0x2029: out += "\\u2029"; break;
      default:
        if (c < 0x20) {
          out += "\\u" + c.toString(16).padStart(4, "0");
        } else {
          out += raw[i];
        }
    }
  }
  out += '"';
  return out;
}

function htmlEscape(raw: string): string {
  let out = "";
  for (const ch of raw) {
    switch (ch) {
      case "&": out += "&amp;"; break;
      case "<": out += "&lt;"; break;
      case ">": out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case "'": out += "&#39;"; break;
      default: out += ch;
    }
  }
  return out;
}
