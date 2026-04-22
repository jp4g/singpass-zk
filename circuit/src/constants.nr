use crate::utils::key_vec;

// Upper bounds on the bytes-of-interest in a Singpass JWS.
pub global MAX_SIGNING_INPUT: u32 = 768;
pub global MAX_PAYLOAD_B64: u32 = 720;
pub global MAX_PAYLOAD_BYTES: u32 = 540;

// Max lengths for JSON claim keys and values.
pub global MAX_KEY_LEN: u32 = 16;
pub global MAX_ISS_LEN: u32 = 64;
pub global MAX_AUD_LEN: u32 = 64;
pub global MAX_NONCE_LEN: u32 = 64;
pub global MAX_SUB_LEN: u32 = 64;

// nodash::pack_bytes<N> returns [Field; N / 31 + 1].
pub global SUB_PACKED_FIELDS: u32 = MAX_SUB_LEN / 31 + 1;       // 3
pub global NONCE_PACKED_FIELDS: u32 = MAX_NONCE_LEN / 31 + 1;   // 3
pub global ISS_PACKED_FIELDS: u32 = MAX_ISS_LEN / 31 + 1;       // 3
pub global AUD_PACKED_FIELDS: u32 = MAX_AUD_LEN / 31 + 1;       // 3
pub global PUBKEY_PACKED_FIELDS: u32 = 64 / 31 + 1;             // 3

// Preimage layouts for the output hashes.
pub global NULLIFIER_PREIMAGE_LEN: u32 = SUB_PACKED_FIELDS + 1 + NONCE_PACKED_FIELDS + 1;   // 8
pub global ISS_AUD_PREIMAGE_LEN: u32 = ISS_PACKED_FIELDS + 1 + AUD_PACKED_FIELDS + 1;       // 8

// JSON claim keys, built once at comptime so call sites have zero witness
// cost for key construction.
pub mod JWT_KEY {
    use super::{key_vec, MAX_KEY_LEN};

    pub global ISS: BoundedVec<u8, MAX_KEY_LEN> = comptime { key_vec("iss") };
    pub global AUD: BoundedVec<u8, MAX_KEY_LEN> = comptime { key_vec("aud") };
    pub global EXP: BoundedVec<u8, MAX_KEY_LEN> = comptime { key_vec("exp") };
    pub global NONCE: BoundedVec<u8, MAX_KEY_LEN> = comptime { key_vec("nonce") };
    pub global SUB: BoundedVec<u8, MAX_KEY_LEN> = comptime { key_vec("sub") };
}
