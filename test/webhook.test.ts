import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { verifyWebhook, WebhookError } from "../src/index.js";

const SECRET = "whsec_test_supersecret_please_rotate";

function sign(secret: string, ts: string, body: string): string {
  const mac = createHmac("sha256", secret);
  mac.update(ts);
  mac.update(".");
  mac.update(body);
  return "sha256=" + mac.digest("hex");
}

function headers(ts: string, sig: string): Record<string, string> {
  const h: Record<string, string> = {};
  if (ts) h["x-webhook-timestamp"] = ts;
  if (sig) h["x-webhook-signature"] = sig;
  return h;
}

describe("verifyWebhook", () => {
  const body = '{"event":"user.created","userId":"u_1"}';

  it("succeeds on a fresh, well-signed delivery", () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = sign(SECRET, ts, body);
    expect(() => verifyWebhook({ secret: SECRET, headers: headers(ts, sig), body })).not.toThrow();
  });

  it("rejects missing timestamp", () => {
    try {
      verifyWebhook({ secret: SECRET, headers: headers("", "sha256=abc"), body });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WebhookError);
      expect((err as WebhookError).code).toBe("missing_timestamp");
    }
  });

  it("rejects missing signature", () => {
    const ts = String(Math.floor(Date.now() / 1000));
    try {
      verifyWebhook({ secret: SECRET, headers: headers(ts, ""), body });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("missing_signature");
    }
  });

  it("rejects malformed timestamp", () => {
    const sig = sign(SECRET, "not-a-number", body);
    try {
      verifyWebhook({ secret: SECRET, headers: headers("not-a-number", sig), body });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("invalid_timestamp");
    }
  });

  it("rejects stale timestamp (older than tolerance)", () => {
    const ts = "1700000000";
    const sig = sign(SECRET, ts, body);
    try {
      verifyWebhook({
        secret: SECRET,
        headers: headers(ts, sig),
        body,
        now: () => new Date(1700000000_000 + 60 * 60_000), // +1 hour
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("timestamp_out_of_window");
    }
  });

  it("rejects future timestamp (further than tolerance ahead)", () => {
    const futureUnix = 1700000000 + 3600;
    const ts = String(futureUnix);
    const sig = sign(SECRET, ts, body);
    try {
      verifyWebhook({
        secret: SECRET,
        headers: headers(ts, sig),
        body,
        now: () => new Date(1700000000_000),
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("timestamp_out_of_window");
    }
  });

  it("rejects tampered body", () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = sign(SECRET, ts, body);
    const tampered = body.replace("u_1", "u_999");
    try {
      verifyWebhook({ secret: SECRET, headers: headers(ts, sig), body: tampered });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("invalid_signature");
    }
  });

  it("rejects tampered timestamp (signed for different ts)", () => {
    const tsSigned = String(Math.floor(Date.now() / 1000));
    const sig = sign(SECRET, tsSigned, body);
    const tsHeader = String(Math.floor(Date.now() / 1000) + 1);
    try {
      verifyWebhook({ secret: SECRET, headers: headers(tsHeader, sig), body });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("invalid_signature");
    }
  });

  it("rejects wrong secret", () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = sign("different-secret", ts, body);
    try {
      verifyWebhook({ secret: SECRET, headers: headers(ts, sig), body });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("invalid_signature");
    }
  });

  it("rejects signature without sha256= prefix", () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const mac = createHmac("sha256", SECRET);
    mac.update(ts);
    mac.update(".");
    mac.update(body);
    const rawHex = mac.digest("hex");
    try {
      verifyWebhook({ secret: SECRET, headers: headers(ts, rawHex), body });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("invalid_signature");
    }
  });

  it("respects custom tolerance", () => {
    const ts = "1700000000";
    const sig = sign(SECRET, ts, body);
    try {
      verifyWebhook({
        secret: SECRET,
        headers: headers(ts, sig),
        body,
        toleranceMs: 10_000, // 10 seconds
        now: () => new Date(1700000000_000 + 30_000), // +30s
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as WebhookError).code).toBe("timestamp_out_of_window");
    }
  });

  it("accepts Headers instances (Fetch API)", () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = sign(SECRET, ts, body);
    const h = new Headers();
    h.set("X-Webhook-Timestamp", ts);
    h.set("X-Webhook-Signature", sig);
    expect(() => verifyWebhook({ secret: SECRET, headers: h, body })).not.toThrow();
  });

  it("accepts Buffer body", () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = sign(SECRET, ts, body);
    expect(() =>
      verifyWebhook({
        secret: SECRET,
        headers: headers(ts, sig),
        body: Buffer.from(body, "utf8"),
      }),
    ).not.toThrow();
  });
});
