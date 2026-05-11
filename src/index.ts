// Public surface of @manyrows/manyrows-node.

export { Client, ManyRowsError } from "./client.js";
export type {
  ClientOptions,
  ConfigItem,
  FeatureFlag,
  Delivery,
  PermissionResult,
  Member,
  MembersResult,
  ListMembersOptions,
  User,
  UserFieldValue,
  UserResult,
  UserField,
} from "./client.js";

export { verifyToken, bearerToken, mrAtCookie, expressMiddleware } from "./auth.js";
export type {
  VerifyOptions,
  ExpressMiddlewareOptions,
  AuthenticatedRequest,
} from "./auth.js";

export { verifyWebhook, WebhookError } from "./webhook.js";
export type { VerifyWebhookOptions, WebhookHeaders, WebhookErrorCode } from "./webhook.js";

export { decryptSecret, computePublicJwkFingerprint } from "./secrets.js";
export type { SecretEnvelope, PrivateKeyJwk } from "./secrets.js";
