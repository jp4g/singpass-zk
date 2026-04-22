// Mirrors circuit/src/constants.nr. Bump together.
export const MAX_SIGNING_INPUT = 768;
export const MAX_ISS_LEN = 64;
export const MAX_AUD_LEN = 64;
export const MAX_NONCE_LEN = 64;
export const MAX_SUB_LEN = 64;

// nodash::pack_bytes<N> -> [Field; N/31 + 1]
export const PACKED_FIELDS = (maxLen: number) => Math.floor(maxLen / 31) + 1;
