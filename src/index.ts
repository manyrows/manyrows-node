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

export { verifyToken, bearerToken, expressMiddleware } from "./auth.js";
export type {
  VerifyOptions,
  ExpressMiddlewareOptions,
  AuthenticatedRequest,
} from "./auth.js";

export { BffClient, BffError, PublicProxy, OAuthCallbackHtml, dispatchOAuthCallback } from "./bff.js";
export { verifyWebhook, WebhookError } from "./webhook.js";
export type { VerifyWebhookOptions, WebhookHeaders, WebhookErrorCode } from "./webhook.js";
export type {
  BffClientOptions,
  BffSession,
  ClientContext,
  ProxyResponse,
  PublicProxyOptions,
  OAuthCallbackOutcome,
  DispatchOAuthCallbackOptions,
} from "./bff.js";
