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

export { BffClient, BffError, PublicProxy, OAuthCallbackHtml, appendQuery } from "./bff.js";
export type {
  BffClientOptions,
  BffSession,
  ClientContext,
  ProxyResponse,
  PublicProxyOptions,
} from "./bff.js";
