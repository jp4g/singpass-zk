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

// Verify a Singpass OIDC ID token's inner JWS signature AND extract the must-check
// claims from the decoded JSON payload.
//
// Phase 3 (this version) - claims are extracted but NOT YET CONSTRAINED:
//   - No iss/aud byte equality checks
//   - No exp > now check
//   - No nonce equality check
//   - sub is not bound to any commitment / nullifier
//   - The payload bytes are NOT bound to message_hash; a malicious prover could
//     submit any JSON. Binding payload to the signed bytes is the next step.
//
// The extracted values are folded into `claims_digest` so the JSON parser's
// constraints aren't optimized away. This output has no semantic meaning yet.
fn main(
    pubkey_x: pub [u8; 32],
    pubkey_y: pub [u8; 32],
    message_hash: pub [u8; 32],
    signature: [u8; 64],
    payload: [u8; MAX_PAYLOAD_BYTES],
) -> pub Field {
    assert(ecdsa_secp256r1::verify_signature(
        pubkey_x,
        pubkey_y,
        signature,
        message_hash,
    ));

    let json: JSON1kb = JSON1kb::parse_json(payload);

    let iss: BoundedVec<u8, MAX_ISS_LEN> =
        json.get_string_from_path([key_vec("iss")]).unwrap();
    let aud: BoundedVec<u8, MAX_AUD_LEN> =
        json.get_string_from_path([key_vec("aud")]).unwrap();
    let exp: u64 = json.get_number_from_path([key_vec("exp")]).unwrap();
    let nonce: BoundedVec<u8, MAX_NONCE_LEN> =
        json.get_string_from_path([key_vec("nonce")]).unwrap();
    let sub: BoundedVec<u8, MAX_SUB_LEN> =
        json.get_string_from_path([key_vec("sub")]).unwrap();

    // Fold extracted values into a single Field so the parser constraints
    // aren't optimized away. No semantic meaning yet.
    let mut acc: Field = exp as Field;
    for i in 0..MAX_ISS_LEN {
        acc = acc + iss.get_unchecked(i) as Field * (i as Field + 1);
    }
    for i in 0..MAX_AUD_LEN {
        acc = acc + aud.get_unchecked(i) as Field * (i as Field + 1);
    }
    for i in 0..MAX_NONCE_LEN {
        acc = acc + nonce.get_unchecked(i) as Field * (i as Field + 1);
    }
    for i in 0..MAX_SUB_LEN {
        acc = acc + sub.get_unchecked(i) as Field * (i as Field + 1);
    }
    acc
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
