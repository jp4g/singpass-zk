use std::ecdsa_secp256r1;
use json_parser::JSON1kb;

// JSON1kb = JSON<1024, 37, 128, 65, 2>. Predefined in json_parser; handles up to
// 1024 bytes of JSON with 2-field (62-byte) keys.
global MAX_PAYLOAD_BYTES: u32 = 1024;

global MAX_KEY_LEN: u32 = 16;   // longest key we extract is "nonce" (5); pad for safety
global MAX_ISS_LEN: u32 = 64;
global MAX_AUD_LEN: u32 = 64;
global MAX_NONCE_LEN: u32 = 64;
global MAX_SUB_LEN: u32 = 64;

// Public claim outputs. TS verifies these match the expected values derived
// from the known payload. This is a debug/extraction-verification step; the
// real flow will replace these with commitments / nullifiers and constrain
// them in-circuit (iss/aud equality, exp>now, nonce equality, etc.).
pub struct Claims {
    iss: BoundedVec<u8, MAX_ISS_LEN>,
    aud: BoundedVec<u8, MAX_AUD_LEN>,
    exp: u64,
    nonce: BoundedVec<u8, MAX_NONCE_LEN>,
    sub: BoundedVec<u8, MAX_SUB_LEN>,
}

fn main(
    pubkey_x: pub [u8; 32],
    pubkey_y: pub [u8; 32],
    message_hash: pub [u8; 32],
    signature: [u8; 64],
    payload: [u8; MAX_PAYLOAD_BYTES],
) -> pub Claims {
    assert(ecdsa_secp256r1::verify_signature(
        pubkey_x,
        pubkey_y,
        signature,
        message_hash,
    ));

    let json: JSON1kb = JSON1kb::parse_json(payload);

    Claims {
        iss: json.get_string_from_path([key_vec("iss")]).unwrap(),
        aud: json.get_string_from_path([key_vec("aud")]).unwrap(),
        exp: json.get_number_from_path([key_vec("exp")]).unwrap(),
        nonce: json.get_string_from_path([key_vec("nonce")]).unwrap(),
        sub: json.get_string_from_path([key_vec("sub")]).unwrap(),
    }
}

// Build a BoundedVec<u8, MAX_KEY_LEN> from a comptime &str so each call in main
// emits the same BoundedVec shape (required by get_*_from_path's generic).
fn key_vec<let N: u32>(s: str<N>) -> BoundedVec<u8, MAX_KEY_LEN> {
    let bytes: [u8; N] = s.as_bytes();
    let mut storage: [u8; MAX_KEY_LEN] = [0; MAX_KEY_LEN];
    for i in 0..N {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, N)
}
