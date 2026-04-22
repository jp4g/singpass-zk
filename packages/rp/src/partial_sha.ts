import { sha256 } from "@noble/hashes/sha256";

// Must match circuit/src/main.nr MAX_REMAINING (multiple of 64).
// This is the in-circuit bound on raw tail bytes; SHA padding is allocated
// separately inside partial_sha256_var_end's own scratch block, so the whole
// MAX_REMAINING is available for the unpadded tail.
export const MAX_REMAINING = 256;

// RP-side ceiling on total signing input length.
export const MAX_SIGNING_INPUT = 768;

export type PartialSha = {
  state: number[]; // [u32; 8] — SHA-256 intermediate state after `cutoff` bytes
  cutoff: number; // bytes consumed off-circuit (always a multiple of 64)
  tail: Uint8Array; // unpadded bytes after cutoff (length L - cutoff)
  tailLen: number; // tail.length (convenience)
  totalLen: number; // original signing input length
};

const SHA256_IV: number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
  0x1f83d9ab, 0x5be0cd19,
];

/**
 * Split a message into a precomputed-SHA prefix and an in-circuit tail.
 *
 * Throws if the message exceeds MAX_SIGNING_INPUT or if the tail wouldn't fit
 * into MAX_REMAINING after SHA-256 padding.
 */
export function computePartialSha(signingInput: Uint8Array): PartialSha {
  const L = signingInput.length;
  if (L > MAX_SIGNING_INPUT) {
    throw new Error(
      `signing input length ${L} > MAX_SIGNING_INPUT (${MAX_SIGNING_INPUT}). Bump MAX_SIGNING_INPUT in both circuit/src/main.nr and partial_sha.ts.`,
    );
  }

  // Pick the smallest cutoff (multiple of 64) such that the tail fits in MAX_REMAINING.
  //   cutoff ≥ L - MAX_REMAINING  AND  cutoff % 64 == 0
  //   => cutoff = ceil((L - MAX_REMAINING) / 64) * 64, clamped to ≥ 0
  let cutoff = 0;
  if (L > MAX_REMAINING) {
    cutoff = Math.ceil((L - MAX_REMAINING) / 64) * 64;
  }

  let state: number[];
  if (cutoff === 0) {
    state = SHA256_IV.slice();
  } else {
    const h = sha256.create();
    h.update(signingInput.subarray(0, cutoff));
    // @noble/hashes 1.8 exposes SHA-256 working vars as A..H u32 fields.
    const anyH = h as unknown as Record<string, number>;
    state = [anyH.A, anyH.B, anyH.C, anyH.D, anyH.E, anyH.F, anyH.G, anyH.H];
  }

  const tail = signingInput.slice(cutoff);
  return {
    state,
    cutoff,
    tail,
    tailLen: tail.length,
    totalLen: L,
  };
}

/**
 * Pad a tail of length <= MAX_REMAINING to exactly MAX_REMAINING with zeros.
 */
export function padTailToMax(tail: Uint8Array): Uint8Array {
  if (tail.length > MAX_REMAINING) {
    throw new Error(`tail length ${tail.length} > MAX_REMAINING (${MAX_REMAINING})`);
  }
  const out = new Uint8Array(MAX_REMAINING);
  out.set(tail, 0);
  return out;
}
