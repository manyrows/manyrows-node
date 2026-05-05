// Decrypt ManyRows config-secret envelopes server-side.
//
// Usage:
//
//   import { Client, decryptSecret } from "@manyrows/manyrows-node";
//
//   const privateKeyJwk = JSON.parse(process.env.MANYROWS_WORKSPACE_PRIVATE_KEY!);
//   const delivery = await client.getDelivery();
//
//   for (const sec of delivery.config.secrets) {
//     if (!sec.isSet || !sec.envelope) continue;
//     const plaintext = decryptSecret(sec.envelope, privateKeyJwk);
//     // plaintext is a Buffer of JSON-encoded value bytes.
//     // For a string secret you'll get `"hello"` (with quotes) — JSON.parse it.
//     const value = JSON.parse(plaintext.toString("utf8"));
//   }
//
// Algorithm: ECDH P-256 → HKDF-SHA256 (salt "manyrows:secrets:v1",
// info "workspace-fingerprint:<hex>") → AES-256-GCM. Mirrors the
// browser-side encrypt path in the ManyRows admin UI; if those
// constants change, update them here too.

import {
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  type JsonWebKey,
} from "node:crypto";

const HKDF_SALT = Buffer.from("manyrows:secrets:v1", "utf8");
const HKDF_INFO_PREFIX = "workspace-fingerprint:";
const EXPECTED_ALGORITHM = "ECDH-P256+HKDF-SHA256+AES-256-GCM";
const EXPECTED_VERSION = 1;

/**
 * On-the-wire envelope shape produced by the browser at secret-save
 * time. The server returns one of these (as a JSON value) per
 * `delivery.config.secrets[].envelope` entry.
 */
export interface SecretEnvelope {
  v: number;
  alg: string;
  fingerprintSha256: string;
  ephemeralPublicKeyJwk: { kty: string; crv: string; x: string; y: string };
  ivB64: string;
  ciphertextB64: string;
}

/**
 * Customer's workspace private JWK (the one downloaded when the
 * workspace key was generated in the admin UI). Only the fields
 * needed for ECDH derivation are listed.
 */
export interface PrivateKeyJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d: string;
}

/**
 * Decrypt a secret envelope using the workspace private key. Returns
 * a Buffer of the JSON-encoded plaintext exactly as the browser
 * stored it (i.e. for a string-typed secret you get `"hello"` with
 * the quotes — `JSON.parse(plaintext.toString("utf8"))` recovers the
 * typed value).
 *
 * Throws on any mismatch: malformed envelope, wrong algorithm
 * version, base64 decode failures, missing key fields, GCM
 * authentication failure (which covers both ciphertext tamper and
 * wrong-key cases).
 */
export function decryptSecret(envelope: unknown, privateKeyJwk: PrivateKeyJwk): Buffer {
  const env = parseEnvelope(envelope);

  if (env.v !== EXPECTED_VERSION) {
    throw new Error(`manyrows secrets: unsupported envelope version ${env.v}`);
  }
  if (env.alg !== EXPECTED_ALGORITHM) {
    throw new Error(`manyrows secrets: unsupported algorithm "${env.alg}"`);
  }
  if (!env.fingerprintSha256) {
    throw new Error("manyrows secrets: missing fingerprintSha256");
  }

  const privateKey = createPrivateKey({
    key: { ...privateKeyJwk } as JsonWebKey,
    format: "jwk",
  });
  const ephemeralPublic = createPublicKey({
    key: { ...env.ephemeralPublicKeyJwk } as JsonWebKey,
    format: "jwk",
  });

  // ECDH derive shared secret.
  const shared = diffieHellman({ privateKey, publicKey: ephemeralPublic });

  // HKDF-SHA256 → 32-byte AES key. hkdfSync returns ArrayBuffer.
  const info = Buffer.from(HKDF_INFO_PREFIX + env.fingerprintSha256, "utf8");
  const aesKeyAB = hkdfSync("sha256", shared, HKDF_SALT, info, 32);
  const aesKey = Buffer.from(aesKeyAB);

  const iv = Buffer.from(env.ivB64, "base64");
  if (iv.length < 12) {
    throw new Error("manyrows secrets: ivB64 too short");
  }
  const ct = Buffer.from(env.ciphertextB64, "base64");
  if (ct.length < 16) {
    // GCM tag is 16 bytes; anything shorter can't possibly contain ciphertext + tag.
    throw new Error("manyrows secrets: ciphertextB64 too short");
  }

  // WebCrypto AES-GCM appends the 16-byte tag at the end of the
  // ciphertext. Node's createDecipheriv splits them apart.
  const tagLen = 16;
  const tag = ct.subarray(ct.length - tagLen);
  const body = ct.subarray(0, ct.length - tagLen);

  const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(tag);
  try {
    const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
    return plaintext;
  } catch {
    // Wrong key, tampered ciphertext, fingerprint mismatch all land here.
    // Don't leak which.
    throw new Error("manyrows secrets: decrypt failed (signature mismatch or wrong key)");
  }
}

function parseEnvelope(raw: unknown): SecretEnvelope {
  let env: any = raw;
  if (typeof raw === "string") {
    try {
      env = JSON.parse(raw);
    } catch {
      throw new Error("manyrows secrets: malformed envelope JSON");
    }
  }
  if (env == null || typeof env !== "object") {
    throw new Error("manyrows secrets: envelope must be an object or JSON string");
  }
  if (typeof env.v !== "number") throw new Error("manyrows secrets: missing v");
  if (typeof env.alg !== "string") throw new Error("manyrows secrets: missing alg");
  if (typeof env.fingerprintSha256 !== "string") throw new Error("manyrows secrets: missing fingerprintSha256");
  if (!env.ephemeralPublicKeyJwk || typeof env.ephemeralPublicKeyJwk !== "object") {
    throw new Error("manyrows secrets: missing ephemeralPublicKeyJwk");
  }
  if (typeof env.ivB64 !== "string") throw new Error("manyrows secrets: missing ivB64");
  if (typeof env.ciphertextB64 !== "string") throw new Error("manyrows secrets: missing ciphertextB64");
  return env as SecretEnvelope;
}

/**
 * Compute the canonical SHA-256 fingerprint of a public JWK (sorted
 * keys: crv, kty, x, y → SHA-256 hex). Useful for verifying the
 * fingerprint shown in the admin UI matches the JWK you have on
 * disk. Not required for normal decryption.
 */
export function computePublicJwkFingerprint(publicJwk: { kty: string; crv: string; x: string; y: string }): string {
  const canonical = JSON.stringify({
    crv: publicJwk.crv,
    kty: publicJwk.kty,
    x: publicJwk.x,
    y: publicJwk.y,
  });
  return createHash("sha256").update(canonical).digest("hex");
}
