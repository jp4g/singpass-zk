import { compactDecrypt, compactVerify, importJWK } from "jose";
import { b64urlDecode, fromUtf8, toHex, utf8 } from "./b64.ts";
import type { Jwk } from "@singpass-zk/driver/src/keys.ts";

// secp256r1 / prime256v1 / P-256 group order. Used for s-low normalization.
const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

type JwsPartsB64u = {
  header: string;
  payload: string;
  signature: string;
};

export type IdTokenHeader = {
  alg?: string;
  kid?: string;
  typ?: string;
};

// Subset of the Singpass FAPI ID token claims the circuit reads. Other
// claims (iat, nbf, acr, ...) may be present; we don't surface them.
export type IdTokenPayload = {
  iss: string;
  aud: string;
  sub: string;
  exp: number;
  nonce: string;
};

export type VerifiedIdToken = {
  jws: JwsPartsB64u;
  header: IdTokenHeader;
  payload: IdTokenPayload;
  // Bytes the circuit's SHA-256 covers: `${jws.header}.${jws.payload}` UTF-8.
  signingInput: Uint8Array;
  // Raw r||s, each 32 bytes big-endian, normalized to low-s.
  signature64: Uint8Array;
  // Issuer signing key uncompressed coords, 32 bytes each.
  pubX: Uint8Array;
  pubY: Uint8Array;
};

export async function decryptAndVerify(
  idTokenJwe: string,
  rpEncPrivateJwk: Jwk,
  issuerJwks: { keys: Jwk[] },
): Promise<VerifiedIdToken> {
  const encKey = await importJWK(rpEncPrivateJwk);
  const { plaintext } = await compactDecrypt(idTokenJwe, encKey);
  const jwsCompact = fromUtf8(plaintext);
  const jws = splitJwsCompact(jwsCompact);

  const header = JSON.parse(
    fromUtf8(b64urlDecode(jws.header)),
  ) as IdTokenHeader;
  if (header.alg !== "ES256") {
    throw new Error(`expected alg=ES256, got ${header.alg}`);
  }

  const issuerJwk = issuerJwks.keys.find(
    (k) => k.kid === header.kid && k.use === "sig",
  );
  if (!issuerJwk) {
    throw new Error(`no issuer signing JWK found with kid=${header.kid}`);
  }
  if (issuerJwk.crv !== "P-256") {
    throw new Error(`expected crv=P-256 JWK, got ${issuerJwk.crv}`);
  }

  // Off-circuit signature verification — fast-fail before we shape circuit
  // inputs. The circuit re-verifies in-circuit; this is defense-in-depth
  // and gives a clear error for malformed JWS.
  const verifyKey = await importJWK(issuerJwk, "ES256");
  const { payload: payloadBytes } = await compactVerify(jwsCompact, verifyKey);
  const payload = JSON.parse(
    fromUtf8(new Uint8Array(payloadBytes)),
  ) as IdTokenPayload;

  const signature64Raw = b64urlDecode(jws.signature);
  if (signature64Raw.length !== 64) {
    throw new Error(`expected 64-byte signature, got ${signature64Raw.length}`);
  }

  const pubX = b64urlDecode(issuerJwk.x!);
  const pubY = b64urlDecode(issuerJwk.y!);
  if (pubX.length !== 32 || pubY.length !== 32) {
    throw new Error(
      `expected 32-byte pubkey coords, got x=${pubX.length} y=${pubY.length}`,
    );
  }

  return {
    jws,
    header,
    payload,
    signingInput: utf8(`${jws.header}.${jws.payload}`),
    signature64: normalizeSLow(signature64Raw),
    pubX,
    pubY,
  };
}

function splitJwsCompact(jws: string): JwsPartsB64u {
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error(`expected 3-part JWS, got ${parts.length}`);
  }
  const [header, payload, signature] = parts as [string, string, string];
  return { header, payload, signature };
}

// Normalize an ECDSA P-256 signature to low-s form. Some signers (notably
// MockPass) produce high-s signatures that are valid per RFC 6979 but get
// rejected by strict verifiers. The Noir circuit's verifier follows
// secp256r1's strict-low-s rule, so we normalize off-circuit.
function normalizeSLow(sig: Uint8Array): Uint8Array {
  const r = sig.slice(0, 32);
  let s = sig.slice(32, 64);
  const sBig = BigInt("0x" + toHex(s));
  if (sBig > P256_N / 2n) {
    s = bigIntTo32Bytes(P256_N - sBig);
  }
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(s, 32);
  return out;
}

function bigIntTo32Bytes(n: bigint): Uint8Array {
  let hex = n.toString(16);
  if (hex.length > 64) throw new Error("scalar too large for 32 bytes");
  hex = hex.padStart(64, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}
