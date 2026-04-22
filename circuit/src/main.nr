mod constants;
mod utils;

use std::ecdsa_secp256r1;
use json_parser::JSON1kb;
use sha256::sha256_var;
use base64::BASE64_URL_DECODER;

use constants::{
    JWT_KEY, MAX_AUD_LEN, MAX_ISS_LEN, MAX_NONCE_LEN,
    MAX_PAYLOAD_B64, MAX_PAYLOAD_BYTES, MAX_SIGNING_INPUT, MAX_SUB_LEN,
};
use utils::{compute_iss_aud_hash, compute_key_hash, compute_nullifier};

// Public outputs:
//   key_hash      - poseidon2 over packed pubkey bytes. Verifier matches
//                   against known Singpass pubkey hash(es) to reject
//                   unrelated signers.
//   iss_aud_hash  - poseidon2 over (iss, aud). Verifier pins to a specific
//                   (issuer, client_id) pair.
//   nullifier     - poseidon2 over (sub, nonce). Session-scoped identity
//                   handle.
//   exp           - token expiry. Verifier checks exp > now off-circuit.
pub struct SignPassOutput {
    key_hash: Field,
    iss_aud_hash: Field,
    nullifier: Field,
    exp: u64,
}

fn main(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature: [u8; 64],
    signing_input: [u8; MAX_SIGNING_INPUT],
    signing_input_len: u32,
    header_b64_len: u32,
) -> pub SignPassOutput {
    // 1. Assert the `.` separator sits at the offset the caller claims.
    //    (Base64url alphabet has no `.`, so a valid signing_input has
    //    exactly one `.` and the ECDSA check below pins which bytes we're
    //    working with; this is a fast-fail sanity check, not a source of
    //    security.)
    assert(signing_input[header_b64_len] == 0x2E);

    // 2. Compute SHA-256 of the signing_input bytes in-circuit. Variable
    //    length up to MAX_SIGNING_INPUT; pads + hashes internally per the
    //    `signing_input_len` witness.
    let message_hash: [u8; 32] = sha256_var(signing_input, signing_input_len);

    // 3. Verify the ECDSA signature over the computed digest. This is the
    //    anchor: if signing_input is altered by one byte, message_hash
    //    changes and this assert fails.
    assert(ecdsa_secp256r1::verify_signature(
        pubkey_x,
        pubkey_y,
        signature,
        message_hash,
    ));

    // 4. Slice the base64url-encoded payload out of signing_input
    //    (everything after the `.`) into a BoundedVec. Conditional *writes*
    //    into large arrays are expensive, so we do an unconditional write
    //    with the *source* index clamped to MAX_SIGNING_INPUT - 1 when out
    //    of range. The dumper zero-pads signing_input past signing_input_len,
    //    so the clamped slot is guaranteed 0; tail slots of payload_b64
    //    storage stay 0, which is what decode_var requires past `len`.
    assert(signing_input_len < MAX_SIGNING_INPUT);
    let payload_b64_len = signing_input_len - header_b64_len - 1;
    let mut payload_b64_storage: [u8; MAX_PAYLOAD_B64] = [0; MAX_PAYLOAD_B64];
    let payload_b64_start = header_b64_len + 1;
    for i in 0..MAX_PAYLOAD_B64 {
        let mut src_idx = payload_b64_start + i as u32;
        if src_idx >= signing_input_len {
            src_idx = MAX_SIGNING_INPUT - 1;
        }
        payload_b64_storage[i] = signing_input[src_idx];
    }
    
    let payload_b64: BoundedVec<u8, MAX_PAYLOAD_B64> =
        BoundedVec::from_parts_unchecked(payload_b64_storage, payload_b64_len);

    // 5. Base64url-no-pad decode the payload into raw JSON bytes.
    let payload_bv: BoundedVec<u8, MAX_PAYLOAD_BYTES> =
        BASE64_URL_DECODER::decode_var(payload_b64);

    // 6. Promote the BoundedVec into a fixed-size byte array for the JSON
    //    parser, filling the tail with 0x20 (space) rather than zeros so
    //    the JSON scanner sees trailing whitespace instead of invalid
    //    tokens. Unconditional write with openbanking-style clamped index:
    //    in-range iterations go to `i`, out-of-range iterations pile onto
    //    `safe_idx`, then we unconditionally restore `safe_idx` to 0x20.
    //    The assert pins one slot of headroom so `safe_idx` never aliases
    //    a real payload byte.
    assert(payload_bv.len() < MAX_PAYLOAD_BYTES);
    let mut payload: [u8; MAX_PAYLOAD_BYTES] = [0x20; MAX_PAYLOAD_BYTES];
    let safe_idx = MAX_PAYLOAD_BYTES - 1;
    for i in 0..MAX_PAYLOAD_BYTES {
        let mut dst = i;
        if (i as u32) >= payload_bv.len() {
            dst = safe_idx;
        }
        payload[dst] = payload_bv.get_unchecked(i);
    }
    payload[safe_idx] = 0x20;

    // 7. Parse the JSON payload.
    let json: JSON1kb = JSON1kb::parse_json(payload);

    // 8. Pull out the five claims we care about: issuer, audience,
    //    expiry, session nonce, subject.
    let iss: BoundedVec<u8, MAX_ISS_LEN> = json.get_string_from_path([JWT_KEY::ISS]).unwrap();
    let aud: BoundedVec<u8, MAX_AUD_LEN> = json.get_string_from_path([JWT_KEY::AUD]).unwrap();
    let exp: u64 = json.get_number_from_path([JWT_KEY::EXP]).unwrap();
    let nonce: BoundedVec<u8, MAX_NONCE_LEN> = json.get_string_from_path([JWT_KEY::NONCE]).unwrap();
    let sub: BoundedVec<u8, MAX_SUB_LEN> = json.get_string_from_path([JWT_KEY::SUB]).unwrap();

    // 9. Compute the three Poseidon2 commitments the verifier will check
    //    against their known values (pubkey, iss+aud pair, session nonce).
    let key_hash = compute_key_hash(pubkey_x, pubkey_y);
    let iss_aud_hash = compute_iss_aud_hash(iss, aud);
    let nullifier = compute_nullifier(sub, nonce);

    // 10. Emit the public outputs.
    SignPassOutput { key_hash, iss_aud_hash, nullifier, exp }
}
