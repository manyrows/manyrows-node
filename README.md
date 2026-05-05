# @manyrows/manyrows-node

Official Node.js SDK for [ManyRows](https://manyrows.com). Mirrors the surface of [`manyrows-go`](https://github.com/manyrows/manyrows-go).

## Install

```bash
npm install @manyrows/manyrows-node
```

Requires **Node 18+** (uses the global `fetch`). TypeScript types are bundled.

## Client

The client wraps the ManyRows Server API. Requires an API key.

```ts
import { Client } from "@manyrows/manyrows-node";

const client = new Client({
  baseURL: "https://app.manyrows.com",
  workspaceSlug: "your-workspace",
  appId: "your-app-id",
  apiKey: "mr_a1b2c3d4_yourSecretKey",
});
```

### Delivery (config + feature flags)

```ts
const delivery = await client.getDelivery();
// delivery.config.public, delivery.config.private, delivery.config.secrets
// delivery.flags.client, delivery.flags.server
```

### Check permission

```ts
const allowed = await client.hasPermission(userId, "posts:edit");

// Or get the full result:
const result = await client.checkPermission(userId, "posts:edit");
// result.allowed, result.permission, result.accountId
```

### User lookup

```ts
// By ID
const user = await client.getUser(userId);
// user.user.email, user.roles, user.permissions, user.fields

// By email
const user = await client.getUserByEmail("user@example.com");
```

### Members

```ts
const result = await client.listMembers({ page: 0, pageSize: 50 });
// result.members, result.total, result.page, result.pageSize

// Filter by email substring:
const result = await client.listMembers({ page: 0, pageSize: 50, email: "alice" });

// Or the convenience alias:
const result = await client.listMembersByEmail("alice");
```

### User fields

```ts
const fields = await client.listUserFields();
// fields[0].key, fields[0].valueType, fields[0].label
```

### Error handling

Non-2xx responses throw `ManyRowsError`:

```ts
import { ManyRowsError } from "@manyrows/manyrows-node";

try {
  await client.getUser("bogus");
} catch (err) {
  if (err instanceof ManyRowsError) {
    console.log(err.status, err.body);
  }
}
```

## Auth middleware

Validates bearer tokens from your end users by calling the ManyRows `/a/me` endpoint, then attaches the user ID to the request.

### Express

```ts
import express from "express";
import { expressMiddleware, type AuthenticatedRequest } from "@manyrows/manyrows-node";

const app = express();

app.use(expressMiddleware({
  baseURL: "https://app.manyrows.com",
  workspaceSlug: "your-workspace",
  appId: "your-app-id",
}));

app.get("/api/profile", (req, res) => {
  const userId = (req as AuthenticatedRequest).manyrowsUserId!;
  res.json({ userId });
});
```

For typed `req.manyrowsUserId` everywhere, augment `Express.Request` once:

```ts
declare global {
  namespace Express {
    interface Request {
      manyrowsUserId?: string;
    }
  }
}
```

### Hono / Fastify / Next.js Route Handlers

Use the lower-level `verifyToken`. Returns the user ID on success, `null` if rejected, throws on network/server errors:

```ts
import { verifyToken, bearerToken } from "@manyrows/manyrows-node";

// Hono example:
app.use("*", async (c, next) => {
  const token = bearerToken(c.req.header("Authorization"));
  if (!token) return c.text("Unauthorized", 401);

  try {
    const userId = await verifyToken(token, {
      baseURL: "https://app.manyrows.com",
      workspaceSlug: "your-workspace",
      appId: "your-app-id",
    });
    if (!userId) return c.text("Unauthorized", 401);
    c.set("userId", userId);
    return next();
  } catch {
    return c.text("Unauthorized", 401); // fail closed on network errors
  }
});
```

### Full example (Express + protected routes)

```ts
import express from "express";
import { Client, expressMiddleware, type AuthenticatedRequest } from "@manyrows/manyrows-node";

const client = new Client({
  baseURL: "https://app.manyrows.com",
  workspaceSlug: "my-workspace",
  appId: "my-app-id",
  apiKey: process.env.MANYROWS_API_KEY!,
});

const app = express();

app.use(
  "/api",
  expressMiddleware({
    baseURL: "https://app.manyrows.com",
    workspaceSlug: "my-workspace",
    appId: "my-app-id",
  }),
);

app.get("/api/profile", async (req, res) => {
  const userId = (req as AuthenticatedRequest).manyrowsUserId!;
  const user = await client.getUser(userId);
  res.json({ email: user.user.email, roles: user.roles });
});

app.get("/api/admin", async (req, res) => {
  const userId = (req as AuthenticatedRequest).manyrowsUserId!;
  if (!(await client.hasPermission(userId, "admin:access"))) {
    res.status(403).send("Forbidden");
    return;
  }
  res.send("Welcome, admin");
});

app.listen(3000);
```

## Tier 1 vs full-BFF

The `verifyToken` / `expressMiddleware` helpers above are for **Tier 1**:
AppKit holds an access token in the browser and your backend validates
it on every authed request. Use that when your app is a SPA with no
backend session of its own.

For **full-BFF** (recommended for production): the browser holds only
an HttpOnly session cookie set by your backend; AppKit hits relative
paths on your server, and your handlers forward to ManyRows via
`BffClient` (auth + data calls) and `PublicProxy` (unauthed bootstrap
+ pre-login surface). There is no `expressMiddleware` for BFF mode —
the cookie + proxy pattern replaces it: read the session ID from your
own cookie in each handler, pass it to `bff.proxy*`, propagate the
upstream status to the browser. A 401 from the proxy means the
session expired; clear your cookie and respond 401 yourself.

## BFF Client (full-BFF mode)

`BffClient` calls the ManyRows `/bff/*` server-to-server endpoints — the
"full-BFF" deployment posture where the browser never sees a token, only an
HttpOnly session cookie set by your backend that carries an opaque ManyRows
session ID. AppKit running in the browser hits relative paths on your
server (`/auth/login`, `/auth/google`, `/auth/verify`, `/auth/totp/verify`,
`/auth/passkey/login/{begin,finish}`, `/auth/oauth/callback`,
`/auth/logout`, `/auth/forgot-password`, `/auth/reset-password`,
`/apps/{appId}/a/*` for authed data calls), and your handlers forward each
to ManyRows via `BffClient`.

Always pass through the real browser IP and User-Agent (`ClientContext`)
so per-IP rate limits and audit logs in ManyRows attribute to the actual
user instead of your egress IP.

```ts
import { BffClient } from "@manyrows/manyrows-node";

const bff = new BffClient({
  baseURL: "https://app.manyrows.com",
  clientId: process.env.MANYROWS_BFF_CLIENT_ID!,
  clientSecret: process.env.MANYROWS_BFF_CLIENT_SECRET!,
});

// Inside your /auth/login handler:
const ctx = { clientIp: req.ip, clientUserAgent: req.headers["user-agent"] };
const s = await bff.loginPassword(body.email, body.password, body.rememberMe, ctx);

if (s.totpRequired) {
  res.json({ totpRequired: true, challengeToken: s.challengeToken });
} else {
  // Stash s.sessionId in your own HttpOnly cookie (or framework session).
  req.session.manyrowsSessionId = s.sessionId;
  res.json({ ok: true });
}
```

### Forwarding authed AppKit data calls

```ts
// Your /apps/{appId}/a/* handler:
const r = await bff.proxyGet(req.session.manyrowsSessionId, "/me", {
  clientIp: req.ip,
  clientUserAgent: req.headers["user-agent"],
});
res.status(r.status).type(r.contentType).send(r.body);
```

POST/PUT/PATCH/DELETE: `bff.proxyPost(sessionId, path, body, ctx)` or
`bff.proxy(method, sessionId, path, body, ctx)`.

### Other login flows

```ts
// Google ID token from GSI:
const s = await bff.loginGoogle(idToken, rememberMe, ctx);

// Email-OTP verify (registration when appId is non-null):
const s = await bff.verifyOtp(email, code, appId, rememberMe, ctx);
if (s.passwordAlreadySet) {
  // Existing user re-verifying — skip the "set your password" screen.
}

// Passkey:
const begin = await bff.passkeyLoginBegin(ctx); // pass straight to the browser
const s = await bff.passkeyLoginFinish(challengeId, response, rememberMe, ctx);

// Apple/Microsoft/GitHub OAuth callback (after ManyRows redirects to your
// /auth/oauth/callback?code=...). See `OAuthCallbackHtml` below for the
// popup-aware response page AppKit expects.
const s = await bff.exchangeAuthCode(code, redirectUri, ctx);

// Logout:
await bff.logout(sessionId, ctx);
delete req.session.manyrowsSessionId;
```

## Popup-aware OAuth callback HTML

AppKit (in BFF mode) opens Apple/Microsoft/GitHub sign-in in a popup.
After ManyRows redirects the popup to your `/auth/oauth/callback?code=...`,
your handler must serve a specific HTML page that postMessages the
opener (or, when there's no opener, redirects the current tab):

```ts
import { OAuthCallbackHtml, BffError } from "@manyrows/manyrows-node";

app.get("/auth/oauth/callback", async (req, res) => {
  const code = req.query.code as string | undefined;
  const error = req.query.error as string | undefined;
  let html: string;

  if (error) {
    html = OAuthCallbackHtml.error(error, "/login?failed=1");
  } else {
    try {
      const s = await bff.exchangeAuthCode(code!, redirectUri, ctx);
      if (s.totpRequired) {
        html = OAuthCallbackHtml.totp(s.challengeToken!, "/login/totp", "/login?failed=1");
      } else {
        req.session.manyrowsSessionId = s.sessionId;
        html = OAuthCallbackHtml.success(s.userId, !!s.totpSetupRequired, "/");
      }
    } catch (err) {
      html = OAuthCallbackHtml.error("exchange_failed", "/login?failed=1");
    }
  }

  res.type("text/html").set("Cache-Control", "no-store").send(html);
});
```

## Public proxies for AppKit boot + pre-login auth

AppKit also hits two unauthenticated endpoints on your backend that
forward to ManyRows: `/apps/{appId}` (public app config) and
`/apps/{appId}/auth/*` (OAuth authorize, OTP request, password reset
discovery, etc.). Use `PublicProxy`:

```ts
import { PublicProxy } from "@manyrows/manyrows-node";

const pp = new PublicProxy({
  baseURL: "https://app.manyrows.com",
  workspaceSlug: "your-workspace",
});

// /apps/:appId GET handler:
app.get("/apps/:appId", async (req, res) => {
  const r = await pp.appBootGet(req.params.appId);
  res.status(r.status).type(r.contentType).send(r.body);
});

// /apps/:appId/auth/* catch-all (Express syntax):
app.all("/apps/:appId/auth/*", async (req, res) => {
  const suffix = req.path.replace(`/apps/${req.params.appId}/auth`, "");
  const body =
    req.method === "GET" || req.method === "HEAD" ? null : JSON.stringify(req.body);
  const query = req.url.includes("?") ? req.url.split("?")[1] : null;
  const r = await pp.authForward(
    req.params.appId, req.method, suffix, query ?? null, body, "application/json",
  );
  res.status(r.status).type(r.contentType).send(r.body);
});
```

## Session cookie security

`BffClient` returns the session ID; you store it in a browser-facing
cookie. Mark that cookie **HttpOnly + Secure + SameSite=Strict** —
`express-session` defaults to HttpOnly but not Secure or SameSite=Strict
in dev; flip both on for `/auth/*` paths. Without these flags an XSS or
CSRF on your domain hands the attacker a usable session ID.

## Custom fetch

Pass a `fetch` override into either `Client` or `verifyToken` for testing, request tracing, or undici dispatcher injection:

```ts
import { Client } from "@manyrows/manyrows-node";

const client = new Client({
  // ...
  fetch: async (url, init) => {
    console.log("→", init?.method, url);
    return fetch(url, init);
  },
});
```

## License

[MIT](./LICENSE)
