use std::ecdsa_secp256r1;
use json_parser::JSON1kb;
use sha256::sha256_var;
use base64::BASE64_URL_DECODER;

global MAX_SIGNING_INPUT: u32 = 768;
global MAX_PAYLOAD_B64: u32 = 720;
global MAX_PAYLOAD_BYTES: u32 = 540;

global MAX_KEY_LEN: u32 = 16;
global MAX_ISS_LEN: u32 = 64;
global MAX_AUD_LEN: u32 = 64;
global MAX_NONCE_LEN: u32 = 64;
global MAX_SUB_LEN: u32 = 64;

// Public outputs. iss/aud/nonce no longer exposed - they are pinned by the
// equality checks against expected public inputs. sub and exp stay for
// app-level consumption.
pub struct Claims {
    sub: BoundedVec<u8, MAX_SUB_LEN>,
    exp: u64,
}

// Verify a Singpass OIDC ID token AND enforce the standard claim checks:
//   - iss   == expected_iss
//   - aud   == expected_aud
//   - nonce == expected_nonce
//   - exp   > now
//
// Binding chain (see previous commit):
//   signing_input bytes -> sha256_var -> message_hash -> ECDSA -> signature
//                       \-> payload_b64 tail -> base64url decode -> JSON parse -> claims
//
// Still Phase 3: sub exposed raw instead of as a per-app commitment / nullifier.
fn main(
    pubkey_x: pub [u8; 32],
    pubkey_y: pub [u8; 32],
    expected_iss: pub BoundedVec<u8, MAX_ISS_LEN>,
    expected_aud: pub BoundedVec<u8, MAX_AUD_LEN>,
    expected_nonce: pub BoundedVec<u8, MAX_NONCE_LEN>,
    now: pub u64,
    signature: [u8; 64],
    signing_input: [u8; MAX_SIGNING_INPUT],
    signing_input_len: u32,
    header_b64_len: u32,
) -> pub Claims {
    // 1. Assert the period separator is where the caller claims it is.
    assert(signing_input[header_b64_len] == 0x2E);

    // 2. SHA-256 in-circuit.
    let message_hash: [u8; 32] = sha256_var(signing_input, signing_input_len);

    // 3. ECDSA over the computed digest.
    assert(ecdsa_secp256r1::verify_signature(
        pubkey_x,
        pubkey_y,
        signature,
        message_hash,
    ));

    // 4. Extract payload_b64 from signing_input.
    let payload_b64_len = signing_input_len - header_b64_len - 1;
    let mut payload_b64_storage: [u8; MAX_PAYLOAD_B64] = [0; MAX_PAYLOAD_B64];
    let payload_b64_start = header_b64_len + 1;
    for i in 0..MAX_PAYLOAD_B64 {
        let src_idx = payload_b64_start + i as u32;
        let in_range = src_idx < signing_input_len;
        if in_range {
            payload_b64_storage[i] = signing_input[src_idx];
        }
    }
    let payload_b64: BoundedVec<u8, MAX_PAYLOAD_B64> =
        BoundedVec::from_parts_unchecked(payload_b64_storage, payload_b64_len);

    // 5. Base64url-no-pad decode.
    let payload_bv: BoundedVec<u8, MAX_PAYLOAD_BYTES> =
        BASE64_URL_DECODER::decode_var(payload_b64);

    // 6. Space-pad for the JSON scanner.
    let mut payload: [u8; MAX_PAYLOAD_BYTES] = [0x20; MAX_PAYLOAD_BYTES];
    for i in 0..MAX_PAYLOAD_BYTES {
        if (i as u32) < payload_bv.len() {
            payload[i] = payload_bv.get_unchecked(i);
        }
    }

    // 7. Parse + extract.
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

    // 8. Enforce claim checks.
    assert(bv_eq(iss, expected_iss), "iss mismatch");
    assert(bv_eq(aud, expected_aud), "aud mismatch");
    assert(bv_eq(nonce, expected_nonce), "nonce mismatch");
    assert(exp > now, "token expired");

    Claims { sub, exp }
}

fn key_vec<let N: u32>(s: str<N>) -> BoundedVec<u8, MAX_KEY_LEN> {
    let bytes: [u8; N] = s.as_bytes();
    let mut storage: [u8; MAX_KEY_LEN] = [0; MAX_KEY_LEN];
    for i in 0..N {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, N)
}

// Length-aware byte equality. BoundedVec's built-in Eq compares ALL storage
// bytes including the tail beyond `len`, which would require callers to
// zero-pad identically. This compares only the first `len` bytes and the
// lengths themselves.
fn bv_eq<let N: u32>(a: BoundedVec<u8, N>, b: BoundedVec<u8, N>) -> bool {
    let mut eq: bool = a.len() == b.len();
    for i in 0..N {
        let in_range = (i as u32) < a.len();
        let byte_eq = a.get_unchecked(i) == b.get_unchecked(i);
        eq = eq & (!in_range | byte_eq);
    }
    eq
}
