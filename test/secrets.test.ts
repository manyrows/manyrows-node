import { describe, it, expect } from "vitest";
import {
  createCipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type JsonWebKey,
} from "node:crypto";
import {
  decryptSecret,
  computePublicJwkFingerprint,
  type SecretEnvelope,
  type PrivateKeyJwk,
} from "../src/index.js";

const HKDF_SALT = Buffer.from("manyrows:secrets:v1", "utf8");
const HKDF_INFO_PREFIX = "workspace-fingerprint:";

interface TestKeypair {
  privateJwk: PrivateKeyJwk;
  publicJwk: { kty: string; crv: string; x: string; y: string };
  fingerprint: string;
}

function generateKeypair(): TestKeypair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateJwk = privateKey.export({ format: "jwk" }) as any;
  const publicJwk = publicKey.export({ format: "jwk" }) as any;
  const fingerprint = computePublicJwkFingerprint({
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
    y: publicJwk.y,
  });
  return { privateJwk, publicJwk, fingerprint };
}

// Browser-side encrypt for tests. Mirrors
// manyrows-ui/src/project/ConfigKeys.tsx::encryptSecretValueToEnvelope.
function encryptForTest(plaintext: Buffer, kp: TestKeypair): SecretEnvelope {
  const wsPub = createPublicKey({ key: kp.publicJwk as JsonWebKey, format: "jwk" });
  const ephem = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const ephemPubJwk = ephem.publicKey.export({ format: "jwk" }) as any;

  const shared = diffieHellman({ privateKey: ephem.privateKey, publicKey: wsPub });
  const info = Buffer.from(HKDF_INFO_PREFIX + kp.fingerprint, "utf8");
  const aesKey = Buffer.from(hkdfSync("sha256", shared, HKDF_SALT, info, 32));

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // WebCrypto-style: tag appended to ciphertext.
  const ct = Buffer.concat([encrypted, tag]);

  return {
    v: 1,
    alg: "ECDH-P256+HKDF-SHA256+AES-256-GCM",
    fingerprintSha256: kp.fingerprint,
    ephemeralPublicKeyJwk: {
      kty: ephemPubJwk.kty,
      crv: ephemPubJwk.crv,
      x: ephemPubJwk.x,
      y: ephemPubJwk.y,
    },
    ivB64: iv.toString("base64"),
    ciphertextB64: ct.toString("base64"),
  };
}

describe("decryptSecret", () => {
  it("round-trips a string value", () => {
    const kp = generateKeypair();
    const env = encryptForTest(Buffer.from(`"hello"`, "utf8"), kp);
    const plaintext = decryptSecret(env, kp.privateJwk);
    expect(plaintext.toString("utf8")).toBe(`"hello"`);
    expect(JSON.parse(plaintext.toString("utf8"))).toBe("hello");
  });

  it("round-trips an object value", () => {
    const kp = generateKeypair();
    const json = JSON.stringify({ db_url: "postgres://localhost", port: 5432 });
    const env = encryptForTest(Buffer.from(json, "utf8"), kp);
    const plaintext = decryptSecret(env, kp.privateJwk);
    expect(plaintext.toString("utf8")).toBe(json);
  });

  it("accepts envelope passed as a JSON string", () => {
    const kp = generateKeypair();
    const env = encryptForTest(Buffer.from(`"hello"`, "utf8"), kp);
    const plaintext = decryptSecret(JSON.stringify(env), kp.privateJwk);
    expect(plaintext.toString("utf8")).toBe(`"hello"`);
  });

  it("rejects tampered ciphertext", () => {
    const kp = generateKeypair();
    const env = encryptForTest(Buffer.from(`"hello"`, "utf8"), kp);
    const ct = Buffer.from(env.ciphertextB64, "base64");
    ct[0] = ct[0] ^ 0xff;
    env.ciphertextB64 = ct.toString("base64");
    expect(() => decryptSecret(env, kp.privateJwk)).toThrow(/decrypt failed/);
  });

  it("rejects wrong private key", () => {
    const kp = generateKeypair();
    const other = generateKeypair();
    const env = encryptForTest(Buffer.from(`"hello"`, "utf8"), kp);
    expect(() => decryptSecret(env, other.privateJwk)).toThrow(/decrypt failed/);
  });

  it("rejects fingerprint mismatch", () => {
    const kp = generateKeypair();
    const env = encryptForTest(Buffer.from(`"hello"`, "utf8"), kp);
    env.fingerprintSha256 = "a".repeat(64);
    expect(() => decryptSecret(env, kp.privateJwk)).toThrow(/decrypt failed/);
  });

  it("rejects unsupported algorithm", () => {
    const kp = generateKeypair();
    const env = encryptForTest(Buffer.from(`"hello"`, "utf8"), kp);
    env.alg = "AES-128-CBC";
    expect(() => decryptSecret(env, kp.privateJwk)).toThrow(/unsupported algorithm/);
  });

  it("rejects unsupported version", () => {
    const kp = generateKeypair();
    const env = encryptForTest(Buffer.from(`"hello"`, "utf8"), kp);
    env.v = 2;
    expect(() => decryptSecret(env, kp.privateJwk)).toThrow(/unsupported envelope version/);
  });

  it("rejects malformed envelope JSON string", () => {
    const kp = generateKeypair();
    expect(() => decryptSecret("not json", kp.privateJwk)).toThrow(/malformed envelope/);
  });

  it("rejects envelope missing required fields", () => {
    const kp = generateKeypair();
    expect(() => decryptSecret({ v: 1, alg: "x" }, kp.privateJwk)).toThrow(/missing/);
  });
});

describe("computePublicJwkFingerprint", () => {
  it("computes a stable hex digest", () => {
    const fp1 = computePublicJwkFingerprint({
      kty: "EC", crv: "P-256",
      x: "WxXEJP0w8e3FKpNi3qwJtBkb1H1bYU2pwLRm6q3a3Ww",
      y: "5y4FJW3LZ1MIK6CuM_kyLQH8UkN7q3KbbpXaWPOkY1Y",
    });
    expect(fp1).toMatch(/^[0-9a-f]{64}$/);

    const fp2 = computePublicJwkFingerprint({
      kty: "EC", crv: "P-256",
      x: "WxXEJP0w8e3FKpNi3qwJtBkb1H1bYU2pwLRm6q3a3Ww",
      y: "5y4FJW3LZ1MIK6CuM_kyLQH8UkN7q3KbbpXaWPOkY1Y",
    });
    expect(fp2).toBe(fp1); // deterministic
  });
});
