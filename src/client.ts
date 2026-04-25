// ManyRows Server API client. Mirrors the surface of manyrows-go's `Client`.

const USER_AGENT = "manyrows-node/1.0";

export interface ClientOptions {
  /** Base URL of the ManyRows service, e.g. "https://app.manyrows.com". */
  baseURL: string;
  /** Workspace slug. */
  workspaceSlug: string;
  /** App ID. */
  appId: string;
  /** API key (from the workspace settings — looks like "mr_xxx_yyy"). */
  apiKey: string;
  /**
   * Optional fetch implementation override. Defaults to the global `fetch`,
   * which is built in to Node 18+. Inject for tests, or to use undici with
   * custom dispatchers, or to wire a request-tracing wrapper.
   */
  fetch?: typeof fetch;
}

/**
 * Thrown for any non-2xx response from the ManyRows API. Inspect `status` and
 * `body` to distinguish auth failures (401), rate limits (429), server errors
 * (5xx), etc.
 */
export class ManyRowsError extends Error {
  status?: number;
  body?: string;

  constructor(message: string, status?: number, body?: string) {
    super(message);
    this.name = "ManyRowsError";
    this.status = status;
    this.body = body;
  }
}

// ===== Delivery =====

export interface ConfigItem {
  key: string;
  type: string;
  value?: unknown;
  /** For `secrets` only: whether a value is configured (the value itself isn't returned). */
  isSet?: boolean;
}

export interface FeatureFlag {
  key: string;
  enabled: boolean;
}

export interface Delivery {
  workspaceId: string;
  projectId: string;
  appId: string;
  updatedAt: string;
  config: {
    public: ConfigItem[];
    private: ConfigItem[];
    secrets: ConfigItem[];
  };
  flags: {
    client: FeatureFlag[];
    server: FeatureFlag[];
  };
}

// ===== Permissions =====

export interface PermissionResult {
  allowed: boolean;
  permission: string;
  accountId: string;
}

// ===== Members =====

export interface Member {
  userId: string;
  email: string;
  name?: string;
  enabled: boolean;
  source: string;
  addedAt: string;
  emailVerifiedAt?: string | null;
  passwordSetAt?: string | null;
  lastLoginAt?: string | null;
  roles: string[];
}

export interface MembersResult {
  members: Member[];
  total: number;
  page: number;
  pageSize: number;
}

export interface ListMembersOptions {
  page?: number;
  pageSize?: number;
  /** Optional email filter (substring match server-side). */
  email?: string;
}

// ===== Users =====

export interface User {
  id: string;
  email: string;
  enabled: boolean;
  source: string;
  emailVerifiedAt?: string | null;
  passwordSetAt?: string | null;
  totpEnabled?: boolean;
}

export interface UserFieldValue {
  id: string;
  projectId?: string;
  userId?: string;
  userFieldId: string;
  value: unknown;
  updatedAt: string;
  updatedBy?: string;
}

export interface UserResult {
  user: User;
  roles: string[];
  permissions: string[];
  fields: UserFieldValue[];
}

// ===== User Fields =====

export interface UserField {
  id: string;
  key: string;
  valueType: "string" | "bool" | "date";
  label?: string;
  status: "active" | "archived";
  visibility?: "client" | "server";
}

// ===== Client =====

export class Client {
  private readonly baseURL: string;
  private readonly workspaceSlug: string;
  private readonly appId: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: ClientOptions) {
    if (!opts.baseURL) throw new Error("manyrows: baseURL is required");
    if (!opts.workspaceSlug) throw new Error("manyrows: workspaceSlug is required");
    if (!opts.appId) throw new Error("manyrows: appId is required");
    if (!opts.apiKey) throw new Error("manyrows: apiKey is required");

    this.baseURL = opts.baseURL.replace(/\/+$/, "");
    this.workspaceSlug = opts.workspaceSlug;
    this.appId = opts.appId;
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /** Build a fully-qualified URL under /x/{workspaceSlug}/api/apps/{appId}{path}. */
  private apiURL(path: string): string {
    return `${this.baseURL}/x/${this.workspaceSlug}/api/apps/${this.appId}${path}`;
  }

  private async doGet<T>(url: string): Promise<T> {
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "GET",
        headers: {
          "X-API-Key": this.apiKey,
          "User-Agent": USER_AGENT,
        },
      });
    } catch (err) {
      throw new ManyRowsError(
        `manyrows: request failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new ManyRowsError(
        `manyrows: ${body || res.statusText} (status ${res.status})`,
        res.status,
        body,
      );
    }

    try {
      return (await res.json()) as T;
    } catch (err) {
      throw new ManyRowsError(
        `manyrows: failed to decode response: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // === Delivery ===

  /** Returns config keys + feature flags for this app. */
  async getDelivery(): Promise<Delivery> {
    return this.doGet<Delivery>(this.apiURL("/"));
  }

  // === Permissions ===

  /** Checks whether a user has a specific permission. */
  async checkPermission(accountId: string, permission: string): Promise<PermissionResult> {
    const params = new URLSearchParams({ accountId, permission });
    return this.doGet<PermissionResult>(`${this.apiURL("/check-permission")}?${params}`);
  }

  /** Convenience: returns just the boolean from `checkPermission`. */
  async hasPermission(accountId: string, permission: string): Promise<boolean> {
    const r = await this.checkPermission(accountId, permission);
    return r.allowed;
  }

  // === Members ===

  /**
   * Returns paginated members for the app. Pass `email` to filter (substring match).
   * Defaults: page 0, pageSize 50.
   */
  async listMembers(opts: ListMembersOptions = {}): Promise<MembersResult> {
    const params = new URLSearchParams({
      page: String(opts.page ?? 0),
      pageSize: String(opts.pageSize ?? 50),
    });
    if (opts.email) params.set("email", opts.email);
    return this.doGet<MembersResult>(`${this.apiURL("/members")}?${params}`);
  }

  /** Convenience for `listMembers({ email, page, pageSize })`. */
  async listMembersByEmail(
    email: string,
    opts: { page?: number; pageSize?: number } = {},
  ): Promise<MembersResult> {
    return this.listMembers({ ...opts, email });
  }

  // === Users ===

  /** Look up a user by ID. */
  async getUser(userId: string): Promise<UserResult> {
    const params = new URLSearchParams({ id: userId });
    return this.doGet<UserResult>(`${this.apiURL("/users")}?${params}`);
  }

  /** Look up a user by email within the app's auth scope. */
  async getUserByEmail(email: string): Promise<UserResult> {
    const params = new URLSearchParams({ email });
    return this.doGet<UserResult>(`${this.apiURL("/users")}?${params}`);
  }

  // === User Fields ===

  /** Returns all user field definitions for the app. */
  async listUserFields(): Promise<UserField[]> {
    const data = await this.doGet<{ userFields: UserField[] }>(this.apiURL("/user-fields"));
    return data.userFields ?? [];
  }
}
