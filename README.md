# @manyrows/manyrows-node

Official Node.js SDK for [ManyRows](https://manyrows.com). Mirrors the surface of [`manyrows-go`](https://github.com/manyrows/manyrows-go).

The examples below assume a self-hosted deployment at
`https://manyrows.example.com`. Swap in whatever host your install
runs on (`http://localhost:3000` for local development, your own
domain in production).

## Install

This SDK is **not yet on npm**. Clone, build, and install the
tarball into your project:

```bash
git clone https://github.com/manyrows/manyrows-node.git
cd manyrows-node
npm install
npm run build
npm pack
# → manyrows-manyrows-node-1.0.0.tgz
```

Then from your application:

```bash
npm install /path/to/manyrows-manyrows-node-1.0.0.tgz
```

(`dist/` is not committed, so `npm install github:manyrows/manyrows-node`
would skip the build and leave no entry point — go through `npm pack`.)

Requires **Node 18+** (uses the global `fetch`). TypeScript types are bundled.

## Client

The client wraps the ManyRows Server API. Requires an API key.

```ts
import { Client } from "@manyrows/manyrows-node";

const client = new Client({
  baseURL: "https://manyrows.example.com",
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

### Decrypt secrets

Secret values are returned as encrypted envelopes. Decrypt them with
your workspace private key (downloaded once when you generated the
workspace key in your install's admin UI):

```ts
import { Client, decryptSecret, type PrivateKeyJwk } from "@manyrows/manyrows-node";

const privateKeyJwk: PrivateKeyJwk = JSON.parse(process.env.MANYROWS_WORKSPACE_PRIVATE_KEY!);
const delivery = await client.getDelivery();

for (const sec of delivery.config.secrets) {
  if (!sec.isSet || !sec.envelope) continue;
  const plaintext = decryptSecret(sec.envelope, privateKeyJwk);
  // plaintext is a Buffer of the JSON-encoded value. For a string
  // secret you'll get `"hello"` (with quotes) — JSON.parse to recover.
  const value = JSON.parse(plaintext.toString("utf8"));
}
```

The private key never leaves your server — secrets are decrypted in
process. See `src/secrets.ts` for the full algorithm (ECDH P-256 +
HKDF-SHA256 + AES-256-GCM).

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

Verifies the user's JWT **locally** against your install's JWKS — fetches `${baseURL}/.well-known/jwks.json` once, caches the keys in-process, refetches on a kid mismatch. No per-request round trip to ManyRows. Falls back to the `mr_at` HttpOnly cookie when no `Authorization: Bearer` header is present (cookie-mode AppKit deploys).

Built on [`jose`](https://github.com/panva/jose) — the de-facto Node JWT library. Zero transitive deps.

### Express

```ts
import express from "express";
import { expressMiddleware, type AuthenticatedRequest } from "@manyrows/manyrows-node";

const app = express();

app.use(expressMiddleware({
  baseURL: "https://manyrows.example.com",
  workspaceSlug: "your-workspace",
  appId: "your-app-id",
}));

app.get("/api/profile", (req, res) => {
  const userId = (req as AuthenticatedRequest).manyrowsUserId!;
  res.json({ userId });
});
```

The middleware accepts the JWT from either:
1. `Authorization: Bearer <jwt>` (local mode / Tier 1)
2. `mr_at` cookie (cookie-mode AppKit, when the auth host and app host share a registrable domain)

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

Use the lower-level `verifyToken` and the two header-extraction helpers. `verifyToken` returns the user ID (`sub`) on success, `null` for any verification failure (expired, malformed, wrong signature, missing `sub`):

```ts
import { verifyToken, bearerToken, mrAtCookie } from "@manyrows/manyrows-node";

// Hono example — supports both Bearer and mr_at cookie:
app.use("*", async (c, next) => {
  const token =
    bearerToken(c.req.header("Authorization")) ??
    mrAtCookie(c.req.header("Cookie"));
  if (!token) return c.text("Unauthorized", 401);

  const userId = await verifyToken(token, {
    baseURL: "https://manyrows.example.com",
    workspaceSlug: "your-workspace",
    appId: "your-app-id",
  });
  if (!userId) return c.text("Unauthorized", 401);
  c.set("userId", userId);
  return next();
});
```

### Full example (Express + protected routes)

```ts
import express from "express";
import { Client, expressMiddleware, type AuthenticatedRequest } from "@manyrows/manyrows-node";

const client = new Client({
  baseURL: "https://manyrows.example.com",
  workspaceSlug: "my-workspace",
  appId: "my-app-id",
  apiKey: process.env.MANYROWS_API_KEY!,
});

const app = express();

app.use(
  "/api",
  expressMiddleware({
    baseURL: "https://manyrows.example.com",
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

## Webhook verification

ManyRows signs every outbound webhook delivery. Use `verifyWebhook`
on your receiver:

```ts
import express from "express";
import { verifyWebhook, WebhookError } from "@manyrows/manyrows-node";

app.post(
  "/webhooks/manyrows",
  express.raw({ type: "application/json" }),  // raw body, NOT json
  (req, res) => {
    try {
      verifyWebhook({ secret, headers: req.headers, body: req.body });
    } catch (err) {
      if (err instanceof WebhookError) return res.status(401).send(err.code);
      throw err;
    }
    // body is verified — JSON.parse(req.body) and process
    res.json({ ok: true });
  },
);
```

`verifyWebhook` checks both the HMAC-SHA256 signature (over
`<timestamp>.<body>`) and that `X-Webhook-Timestamp` is within
±5 minutes of now. Pass `toleranceMs` to widen or tighten.

Read the body as **raw bytes** before verifying — re-serializing
parsed JSON changes whitespace and breaks the check.

## License

[MIT](./LICENSE)
