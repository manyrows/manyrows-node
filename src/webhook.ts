// Webhook signature verification helper for inbound deliveries from
// ManyRows.
//
// Usage:
//
//   import { verifyWebhook, WebhookError } from "@manyrows/manyrows-node";
//
//   app.post("/webhooks/manyrows", express.raw({ type: "application/json" }), (req, res) => {
//     try {
//       verifyWebhook({ secret, headers: req.headers, body: req.body });
//     } catch (err) {
//       if (err instanceof WebhookError) return res.status(401).send(err.code);
//       throw err;
//     }
//     // body is verified — JSON.parse(req.body) and process
//     res.json({ ok: true });
//   });
//
// IMPORTANT: read the body as RAW BYTES before verifying. The HMAC
// covers the exact transmitted bytes; re-serializing parsed JSON
// changes whitespace and breaks the check. Use express.raw() (or
// equivalent) on the route, NOT express.json().

import { createHmac, timingSafeEqual } from "node:crypto";

const HEADER_TIMESTAMP = "x-webhook-timestamp";
const HEADER_SIGNATURE = "x-webhook-signature";
const SIGNATURE_PREFIX = "sha256=";
const DEFAULT_TOLERANCE_MS = 5 * 60 * 1000;

/**
 * Failure codes for {@link verifyWebhook}. Map a {@link WebhookError}'s
 * `code` to a log line, a metric tag, or an HTTP status — receivers
 * should reject the delivery on any of these.
 */
export type WebhookErrorCode =
  | "missing_timestamp"
  | "missing_signature"
  | "invalid_timestamp"
  | "timestamp_out_of_window"
  | "invalid_signature";

/**
 * Thrown by {@link verifyWebhook} when a delivery is malformed,
 * tampered, or stale. Inspect `code` to distinguish causes.
 */
export class WebhookError extends Error {
  readonly code: WebhookErrorCode;

  constructor(code: WebhookErrorCode, message: string) {
    super(message);
    this.name = "WebhookError";
    this.code = code;
  }
}

/**
 * Headers shape: anything that exposes a case-insensitive lookup of
 * the timestamp + signature headers. Express (`req.headers`),
 * Fastify, raw `IncomingHttpHeaders`, and `Headers` (the Fetch class)
 * all work.
 */
export type WebhookHeaders =
  | Record<string, string | string[] | undefined>
  | Headers;

export interface VerifyWebhookOptions {
  /** Per-webhook secret from the ManyRows admin UI. */
  secret: string;
  /** Inbound request headers. */
  headers: WebhookHeaders;
  /** Raw request body bytes. Pass a Buffer or the original string. */
  body: Buffer | string;
  /**
   * Accept timestamps within ±tolerance milliseconds of `now()`.
   * Default 5 minutes. Tighten for stricter setups; loosen only if
   * receiver clock drift exceeds 5 min (rare on NTP-synced systems).
   */
  toleranceMs?: number;
  /** Override Date.now() (test hook). */
  now?: () => Date;
}

/**
 * Verifies the HMAC-SHA256 signature and timestamp on an inbound
 * webhook delivery from ManyRows. Throws a {@link WebhookError} on
 * any failure; returns void on success.
 *
 * Signature is computed over the canonical string
 * `<timestamp>.<body>` so a replay of an old delivery is detectable
 * by the timestamp check even if the body itself is unchanged.
 */
export function verifyWebhook(opts: VerifyWebhookOptions): void {
  const tolerance = opts.toleranceMs ?? DEFAULT_TOLERANCE_MS;
  const now = opts.now ?? (() => new Date());

  const tsRaw = headerOf(opts.headers, HEADER_TIMESTAMP);
  if (!tsRaw) throw new WebhookError("missing_timestamp", "missing X-Webhook-Timestamp header");

  const sigRaw = headerOf(opts.headers, HEADER_SIGNATURE);
  if (!sigRaw) throw new WebhookError("missing_signature", "missing X-Webhook-Signature header");

  const tsUnix = Number(tsRaw);
  if (!Number.isFinite(tsUnix) || !Number.isInteger(tsUnix)) {
    throw new WebhookError("invalid_timestamp", "X-Webhook-Timestamp is not an integer");
  }
  const deltaMs = now().getTime() - tsUnix * 1000;
  if (deltaMs < -tolerance || deltaMs > tolerance) {
    throw new WebhookError("timestamp_out_of_window", "X-Webhook-Timestamp is outside the accepted window");
  }

  if (!sigRaw.startsWith(SIGNATURE_PREFIX)) {
    throw new WebhookError("invalid_signature", "X-Webhook-Signature missing 'sha256=' prefix");
  }
  const sigHex = sigRaw.slice(SIGNATURE_PREFIX.length);

  let provided: Buffer;
  try {
    provided = Buffer.from(sigHex, "hex");
    // Buffer.from is permissive — verify the hex actually decoded all of it.
    if (provided.length === 0 || provided.toString("hex") !== sigHex.toLowerCase()) {
      throw new Error("malformed hex");
    }
  } catch {
    throw new WebhookError("invalid_signature", "X-Webhook-Signature is not valid hex");
  }

  const bodyBytes = typeof opts.body === "string" ? Buffer.from(opts.body, "utf8") : opts.body;

  const mac = createHmac("sha256", opts.secret);
  mac.update(tsRaw);
  mac.update(".");
  mac.update(bodyBytes);
  const expected = mac.digest();

  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    throw new WebhookError("invalid_signature", "signature mismatch");
  }
}

function headerOf(headers: WebhookHeaders, name: string): string {
  if (headers instanceof Headers) {
    return (headers.get(name) ?? "").trim();
  }
  // Node IncomingHttpHeaders are lowercase by convention; normalise on lookup
  // anyway to handle frameworks that preserve case.
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === name) {
      const v = (headers as Record<string, string | string[] | undefined>)[k];
      if (Array.isArray(v)) return (v[0] ?? "").trim();
      return (v ?? "").trim();
    }
  }
  return "";
}
