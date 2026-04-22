use nodash::pack_bytes;
use poseidon::poseidon2::Poseidon2;

use crate::constants::{
    AUD_PACKED_FIELDS, ISS_AUD_PREIMAGE_LEN, ISS_PACKED_FIELDS, MAX_AUD_LEN, MAX_ISS_LEN,
    MAX_KEY_LEN, MAX_NONCE_LEN, MAX_SUB_LEN, NONCE_PACKED_FIELDS, NULLIFIER_PREIMAGE_LEN,
    PUBKEY_PACKED_FIELDS, SUB_PACKED_FIELDS,
};

// Build a BoundedVec<u8, MAX_KEY_LEN> from a comptime str literal. Used to
// seed the KEY_* globals in `constants` at compile time.
pub comptime fn key_vec<let N: u32>(s: str<N>) -> BoundedVec<u8, MAX_KEY_LEN> {
    let bytes: [u8; N] = s.as_bytes();
    let mut storage: [u8; MAX_KEY_LEN] = [0; MAX_KEY_LEN];
    for i in 0..N {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, N)
}

// poseidon2(pack(pubkey_x || pubkey_y)).
pub fn compute_key_hash(x: [u8; 32], y: [u8; 32]) -> Field {
    let mut concat: [u8; 64] = [0; 64];
    for i in 0..32 {
        concat[i] = x[i];
        concat[32 + i] = y[i];
    }
    let packed: [Field; PUBKEY_PACKED_FIELDS] = pack_bytes(concat);
    Poseidon2::hash(packed, PUBKEY_PACKED_FIELDS)
}

// poseidon2(pack(iss) || iss.len || pack(aud) || aud.len).
pub fn compute_iss_aud_hash(
    iss: BoundedVec<u8, MAX_ISS_LEN>,
    aud: BoundedVec<u8, MAX_AUD_LEN>,
) -> Field {
    let iss_packed: [Field; ISS_PACKED_FIELDS] = pack_bytes(iss.storage());
    let aud_packed: [Field; AUD_PACKED_FIELDS] = pack_bytes(aud.storage());

    let mut preimage: [Field; ISS_AUD_PREIMAGE_LEN] = [0; ISS_AUD_PREIMAGE_LEN];
    for i in 0..ISS_PACKED_FIELDS {
        preimage[i] = iss_packed[i];
    }
    preimage[ISS_PACKED_FIELDS] = iss.len() as Field;
    for i in 0..AUD_PACKED_FIELDS {
        preimage[ISS_PACKED_FIELDS + 1 + i] = aud_packed[i];
    }
    preimage[ISS_PACKED_FIELDS + 1 + AUD_PACKED_FIELDS] = aud.len() as Field;

    Poseidon2::hash(preimage, ISS_AUD_PREIMAGE_LEN)
}

// poseidon2(pack(sub) || sub.len || pack(nonce) || nonce.len). Session-scoped
// identity handle - same user in a different OIDC session yields a different
// nullifier.
pub fn compute_nullifier(
    sub: BoundedVec<u8, MAX_SUB_LEN>,
    nonce: BoundedVec<u8, MAX_NONCE_LEN>,
) -> Field {
    let sub_packed: [Field; SUB_PACKED_FIELDS] = pack_bytes(sub.storage());
    let nonce_packed: [Field; NONCE_PACKED_FIELDS] = pack_bytes(nonce.storage());

    let mut preimage: [Field; NULLIFIER_PREIMAGE_LEN] = [0; NULLIFIER_PREIMAGE_LEN];
    for i in 0..SUB_PACKED_FIELDS {
        preimage[i] = sub_packed[i];
    }
    preimage[SUB_PACKED_FIELDS] = sub.len() as Field;
    for i in 0..NONCE_PACKED_FIELDS {
        preimage[SUB_PACKED_FIELDS + 1 + i] = nonce_packed[i];
    }
    preimage[SUB_PACKED_FIELDS + 1 + NONCE_PACKED_FIELDS] = nonce.len() as Field;

    Poseidon2::hash(preimage, NULLIFIER_PREIMAGE_LEN)
}
