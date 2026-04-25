# @manyrows/node

Official Node.js SDK for [ManyRows](https://manyrows.com). Mirrors the surface of [`manyrows-go`](https://github.com/manyrows/manyrows-go).

## Install

```bash
npm install @manyrows/node
```

Requires **Node 18+** (uses the global `fetch`). TypeScript types are bundled.

## Client

The client wraps the ManyRows Server API. Requires an API key.

```ts
import { Client } from "@manyrows/node";

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
import { ManyRowsError } from "@manyrows/node";

try {
  await client.getUser("bogus");
} catch (err) {
  if (err instanceof ManyRowsError) {
    console.log(err.status, err.body);
  }
}
```

## Auth middleware

Validates bearer tokens from your end users by calling the ManyRows `/a/app/me` endpoint, then attaches the user ID to the request.

### Express

```ts
import express from "express";
import { expressMiddleware, type AuthenticatedRequest } from "@manyrows/node";

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
import { verifyToken, bearerToken } from "@manyrows/node";

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
import { Client, expressMiddleware, type AuthenticatedRequest } from "@manyrows/node";

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

## Custom fetch

Pass a `fetch` override into either `Client` or `verifyToken` for testing, request tracing, or undici dispatcher injection:

```ts
import { Client } from "@manyrows/node";

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
