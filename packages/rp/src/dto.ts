import type { VerifiedIdToken, JwePartsB64u, JwsPartsB64u } from "./jose.ts";
import type { Jwk } from "@singpass-zk/driver/src/keys.ts";
import { toHex } from "./b64.ts";

// JSON-safe shape of VerifiedIdToken for crossing the Node↔browser boundary.
// Every Uint8Array is hex-encoded; everything else is already JSON-safe.
export type VerifiedIdTokenDto = {
  jwe: JwePartsB64u;
  jws: JwsPartsB64u;
  jwsCompact: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  payloadBytes: string;
  signingInput: string;
  messageHash: string;
  signature64: string;
  r: string;
  s: string;
  issuerJwk: Jwk;
  pubX: string;
  pubY: string;
};

export function serialize(v: VerifiedIdToken): VerifiedIdTokenDto {
  return {
    jwe: v.jwe,
    jws: v.jws,
    jwsCompact: v.jwsCompact,
    header: v.header,
    payload: v.payload,
    payloadBytes: toHex(v.payloadBytes),
    signingInput: toHex(v.signingInput),
    messageHash: toHex(v.messageHash),
    signature64: toHex(v.signature64),
    r: toHex(v.r),
    s: toHex(v.s),
    issuerJwk: v.issuerJwk,
    pubX: toHex(v.pubX),
    pubY: toHex(v.pubY),
  };
}

export function deserialize(dto: VerifiedIdTokenDto): VerifiedIdToken {
  return {
    jwe: dto.jwe,
    jws: dto.jws,
    jwsCompact: dto.jwsCompact,
    header: dto.header,
    payload: dto.payload,
    payloadBytes: fromHex(dto.payloadBytes),
    signingInput: fromHex(dto.signingInput),
    messageHash: fromHex(dto.messageHash),
    signature64: fromHex(dto.signature64),
    r: fromHex(dto.r),
    s: fromHex(dto.s),
    issuerJwk: dto.issuerJwk,
    pubX: fromHex(dto.pubX),
    pubY: fromHex(dto.pubY),
  };
}

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`fromHex: odd length ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
