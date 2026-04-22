use std::ecdsa_secp256r1;
use json_parser::JSON1kb;
use sha256::sha256_var;
use base64::BASE64_URL_DECODER;

// Upper bounds for signing input + derived lengths. signing_input is
// base64url(header) + "." + base64url(payload). Observed MockPass sample ~617
// bytes; bump if production exceeds.
global MAX_SIGNING_INPUT: u32 = 768;
// Biggest possible payload_b64 tail. Bounded by signing input minus the
// smallest realistic header_b64 minus the "." separator.
global MAX_PAYLOAD_B64: u32 = 720;
// Base64url-no-pad: decoded_len = floor(input_len * 3 / 4).
global MAX_PAYLOAD_BYTES: u32 = 540;

global MAX_KEY_LEN: u32 = 16;
global MAX_ISS_LEN: u32 = 64;
global MAX_AUD_LEN: u32 = 64;
global MAX_NONCE_LEN: u32 = 64;
global MAX_SUB_LEN: u32 = 64;

pub struct Claims {
    iss: BoundedVec<u8, MAX_ISS_LEN>,
    aud: BoundedVec<u8, MAX_AUD_LEN>,
    exp: u64,
    nonce: BoundedVec<u8, MAX_NONCE_LEN>,
    sub: BoundedVec<u8, MAX_SUB_LEN>,
}

// Verify a Singpass OIDC ID token's inner JWS signature, then extract the
// must-check claims from the payload.
//
// Binding chain:
//   signing_input bytes  -(sha256_var)->  message_hash  -(ECDSA)->  signature
//                  |
//                  +-> payload_b64 tail -(base64url decode)-> payload JSON
//                                                             |
//                                                             +-> claims
//
// Every piece is now constrained in-circuit. A prover cannot substitute
// signing_input, payload_b64, or the decoded payload without failing one of
// the constraints above.
//
// Remaining Phase-3 gaps (not blockers):
//   - Claims are exposed but not yet CHECKED (iss == expected, aud == our
//     client_id, exp > now, nonce == challenge).
//   - sub is exposed raw rather than as a salted commitment / nullifier.
fn main(
    pubkey_x: pub [u8; 32],
    pubkey_y: pub [u8; 32],
    signature: [u8; 64],
    signing_input: [u8; MAX_SIGNING_INPUT],
    signing_input_len: u32,
    // byte offset of the "." between base64url(header) and base64url(payload)
    header_b64_len: u32,
) -> pub Claims {
    // 1. Assert the period separator is where the RP claims it is.
    assert(signing_input[header_b64_len] == 0x2E);

    // 2. SHA-256 the signing_input bytes in-circuit (variable length).
    let message_hash: [u8; 32] = sha256_var(signing_input, signing_input_len);

    // 3. ECDSA over the computed digest.
    assert(ecdsa_secp256r1::verify_signature(
        pubkey_x,
        pubkey_y,
        signature,
        message_hash,
    ));

    // 4. Extract payload_b64 (signing_input[header_b64_len+1 .. signing_input_len])
    //    into a fixed-capacity BoundedVec.
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

    // 5. Base64url-no-pad decode -> raw payload JSON bytes.
    let payload_bv: BoundedVec<u8, MAX_PAYLOAD_BYTES> =
        BASE64_URL_DECODER::decode_var(payload_b64);

    // 6. Convert to fixed-size array with JSON-whitespace padding beyond len
    //    so the parser's scanner doesn't choke on trailing zeros.
    let mut payload: [u8; MAX_PAYLOAD_BYTES] = [0x20; MAX_PAYLOAD_BYTES];
    for i in 0..MAX_PAYLOAD_BYTES {
        if (i as u32) < payload_bv.len() {
            payload[i] = payload_bv.get_unchecked(i);
        }
    }

    // 7. Parse JSON and extract claims.
    let json: JSON1kb = JSON1kb::parse_json(payload);
    Claims {
        iss: json.get_string_from_path([key_vec("iss")]).unwrap(),
        aud: json.get_string_from_path([key_vec("aud")]).unwrap(),
        exp: json.get_number_from_path([key_vec("exp")]).unwrap(),
        nonce: json.get_string_from_path([key_vec("nonce")]).unwrap(),
        sub: json.get_string_from_path([key_vec("sub")]).unwrap(),
    }
}

fn key_vec<let N: u32>(s: str<N>) -> BoundedVec<u8, MAX_KEY_LEN> {
    let bytes: [u8; N] = s.as_bytes();
    let mut storage: [u8; MAX_KEY_LEN] = [0; MAX_KEY_LEN];
    for i in 0..N {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, N)
}
