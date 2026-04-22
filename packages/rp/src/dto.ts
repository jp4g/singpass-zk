import type {
  IdTokenHeader,
  IdTokenPayload,
  VerifiedIdToken,
} from "./jose.ts";
import { toHex } from "./b64.ts";

// JSON-safe shape of VerifiedIdToken for crossing the Node↔browser boundary.
// Uint8Array fields become hex strings; the rest is already JSON-safe.
export type VerifiedIdTokenDto = {
  jws: { header: string; payload: string; signature: string };
  header: IdTokenHeader;
  payload: IdTokenPayload;
  signingInput: string;
  signature64: string;
  pubX: string;
  pubY: string;
};

export function serialize(v: VerifiedIdToken): VerifiedIdTokenDto {
  return {
    jws: v.jws,
    header: v.header,
    payload: v.payload,
    signingInput: toHex(v.signingInput),
    signature64: toHex(v.signature64),
    pubX: toHex(v.pubX),
    pubY: toHex(v.pubY),
  };
}

export function deserialize(dto: VerifiedIdTokenDto): VerifiedIdToken {
  return {
    jws: dto.jws,
    header: dto.header,
    payload: dto.payload,
    signingInput: fromHex(dto.signingInput),
    signature64: fromHex(dto.signature64),
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
