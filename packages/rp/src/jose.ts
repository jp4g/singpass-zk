import { compactDecrypt, importJWK, compactVerify } from "jose";
import { createHash } from "node:crypto";
import { b64urlDecode, utf8, fromUtf8, toHex } from "./b64.ts";
import type { Jwk } from "@singpass-zk/driver/src/keys.ts";

// P-256 curve order n. Used for s-low normalization.
// secp256r1 / prime256v1 / P-256 order:
const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export type JwePartsB64u = {
  header: string;
  encryptedKey: string;
  iv: string;
  ciphertext: string;
  tag: string;
};

export type JwsPartsB64u = {
  header: string;
  payload: string;
  signature: string;
};

export type VerifiedIdToken = {
  jwe: JwePartsB64u;
  jws: JwsPartsB64u;
  jwsCompact: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  payloadBytes: Uint8Array;
  signingInput: Uint8Array;
  messageHash: Uint8Array;
  signature64: Uint8Array;
  r: Uint8Array;
  s: Uint8Array;
  issuerJwk: Jwk;
  pubX: Uint8Array;
  pubY: Uint8Array;
};

export function splitJweCompact(jwe: string): JwePartsB64u {
  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new Error(`expected 5-part JWE, got ${parts.length}`);
  }
  const [header, encryptedKey, iv, ciphertext, tag] = parts as [
    string,
    string,
    string,
    string,
    string,
  ];
  return { header, encryptedKey, iv, ciphertext, tag };
}

export function splitJwsCompact(jws: string): JwsPartsB64u {
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error(`expected 3-part JWS, got ${parts.length}`);
  }
  const [header, payload, signature] = parts as [string, string, string];
  return { header, payload, signature };
}

export async function decryptAndVerify(
  idTokenJwe: string,
  rpEncPrivateJwk: Jwk,
  issuerJwks: { keys: Jwk[] },
): Promise<VerifiedIdToken> {
  const jweParts = splitJweCompact(idTokenJwe);

  const encKey = await importJWK(rpEncPrivateJwk);
  const { plaintext } = await compactDecrypt(idTokenJwe, encKey);
  // The decrypted plaintext is the inner compact JWS (string bytes).
  const jwsCompact = fromUtf8(plaintext);
  const jwsParts = splitJwsCompact(jwsCompact);

  // Decode JWS header to find kid, then pick the matching key.
  const header = JSON.parse(
    fromUtf8(b64urlDecode(jwsParts.header)),
  ) as Record<string, unknown>;

  const kid = header["kid"];
  const alg = header["alg"];
  if (alg !== "ES256") {
    throw new Error(`expected alg=ES256, got ${alg}`);
  }
  const issuerJwk = issuerJwks.keys.find((k) => k.kid === kid && k.use === "sig");
  if (!issuerJwk) {
    throw new Error(`no issuer signing JWK found with kid=${String(kid)}`);
  }
  if (issuerJwk.crv !== "P-256") {
    throw new Error(`expected crv=P-256 JWK, got ${issuerJwk.crv}`);
  }

  // Off-circuit sanity verify.
  const verifyKey = await importJWK(issuerJwk, "ES256");
  const verified = await compactVerify(jwsCompact, verifyKey);
  const payloadBytes = new Uint8Array(verified.payload);
  const payload = JSON.parse(fromUtf8(payloadBytes)) as Record<
    string,
    unknown
  >;

  // Build exactly the bytes the circuit will hash.
  const signingInput = utf8(`${jwsParts.header}.${jwsParts.payload}`);
  const messageHash = new Uint8Array(
    createHash("sha256").update(signingInput).digest(),
  );

  // JOSE signature for ES256 is already raw r||s, each 32 bytes big-endian.
  const signature64Raw = b64urlDecode(jwsParts.signature);
  if (signature64Raw.length !== 64) {
    throw new Error(`expected 64-byte signature, got ${signature64Raw.length}`);
  }
  const { sig, r, s } = normalizeSLow(signature64Raw);

  const pubX = b64urlDecode(issuerJwk.x!);
  const pubY = b64urlDecode(issuerJwk.y!);
  if (pubX.length !== 32 || pubY.length !== 32) {
    throw new Error(
      `expected 32-byte pubkey coords, got x=${pubX.length} y=${pubY.length}`,
    );
  }

  return {
    jwe: jweParts,
    jws: jwsParts,
    jwsCompact,
    header,
    payload,
    payloadBytes,
    signingInput,
    messageHash,
    signature64: sig,
    r,
    s,
    issuerJwk,
    pubX,
    pubY,
  };
}

function normalizeSLow(sig: Uint8Array): {
  sig: Uint8Array;
  r: Uint8Array;
  s: Uint8Array;
} {
  const r = sig.slice(0, 32);
  let s = sig.slice(32, 64);
  const sBig = bytesToBigInt(s);
  const halfN = P256_N / 2n;
  if (sBig > halfN) {
    const sLow = P256_N - sBig;
    s = bigIntTo32Bytes(sLow);
  }
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(s, 32);
  return { sig: out, r, s };
}

function bytesToBigInt(b: Uint8Array): bigint {
  return BigInt("0x" + toHex(b));
}

function bigIntTo32Bytes(n: bigint): Uint8Array {
  let hex = n.toString(16);
  if (hex.length > 64) throw new Error("scalar too large for 32 bytes");
  hex = hex.padStart(64, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}
