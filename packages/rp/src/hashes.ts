import { poseidon2Hash } from "@zkpassport/poseidon2";
import {
  MAX_AUD_LEN,
  MAX_ISS_LEN,
  MAX_NONCE_LEN,
  MAX_SUB_LEN,
} from "./constants.ts";

// Pack a byte array into 31-byte little-endian field chunks. Mirrors
// nodash::pack_bytes used by the circuit.
function packBytes(bytes: Uint8Array, maxLen: number): bigint[] {
  const fieldCount = Math.floor(maxLen / 31) + 1;
  const out: bigint[] = new Array(fieldCount).fill(0n);
  for (let i = 0; i < fieldCount; i++) {
    let acc = 0n;
    let mul = 1n;
    for (let j = 0; j < 31; j++) {
      const idx = i * 31 + j;
      const byte = idx < maxLen && idx < bytes.length ? bytes[idx] ?? 0 : 0;
      acc += BigInt(byte) * mul;
      mul *= 256n;
    }
    out[i] = acc;
  }
  return out;
}

// poseidon2(pack(pubkey_x || pubkey_y)). Mirrors compute_key_hash.
export function expectedKeyHash(x: Uint8Array, y: Uint8Array): bigint {
  if (x.length !== 32 || y.length !== 32) {
    throw new Error("pubkey coords must be 32 bytes each");
  }
  const concat = new Uint8Array(64);
  concat.set(x, 0);
  concat.set(y, 32);
  return poseidon2Hash(packBytes(concat, 64));
}

// poseidon2(pack(iss) || iss_len || pack(aud) || aud_len). Mirrors
// compute_iss_aud_hash.
export function expectedIssAudHash(iss: string, aud: string): bigint {
  const enc = new TextEncoder();
  const issBytes = enc.encode(iss);
  const audBytes = enc.encode(aud);
  const issZero = new Uint8Array(MAX_ISS_LEN);
  issZero.set(issBytes, 0);
  const audZero = new Uint8Array(MAX_AUD_LEN);
  audZero.set(audBytes, 0);
  return poseidon2Hash([
    ...packBytes(issZero, MAX_ISS_LEN),
    BigInt(issBytes.length),
    ...packBytes(audZero, MAX_AUD_LEN),
    BigInt(audBytes.length),
  ]);
}

// poseidon2(pack(sub) || sub_len || pack(nonce) || nonce_len). Mirrors
// compute_nullifier.
export function expectedNullifier(sub: string, nonce: string): bigint {
  const enc = new TextEncoder();
  const subBytes = enc.encode(sub);
  const nonceBytes = enc.encode(nonce);
  const subZero = new Uint8Array(MAX_SUB_LEN);
  subZero.set(subBytes, 0);
  const nonceZero = new Uint8Array(MAX_NONCE_LEN);
  nonceZero.set(nonceBytes, 0);
  return poseidon2Hash([
    ...packBytes(subZero, MAX_SUB_LEN),
    BigInt(subBytes.length),
    ...packBytes(nonceZero, MAX_NONCE_LEN),
    BigInt(nonceBytes.length),
  ]);
}
