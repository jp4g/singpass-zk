mod partial_hash;

use std::ecdsa_secp256r1;
use partial_hash::partial_sha256_var_end;

// Upper bound on bytes hashed INSIDE the circuit. Must be a multiple of 64.
// Bytes before the cutoff are precomputed off-circuit into `partial_sha_state`.
// 256 covers up to 4 final blocks plus SHA-256 padding (9 bytes overhead).
// The RP-side MAX_SIGNING_INPUT (currently 768) caps the *total* signing input.
global MAX_REMAINING: u32 = 256;

// Verify a Singpass OIDC ID token's inner JWS signature with SHA-256
// computed inside the circuit (partial-SHA technique adapted from zkemail.nr).
//
// The off-circuit RP precomputes the SHA-256 intermediate state over the first
// `cutoff` bytes of the signing input (cutoff = K * 64). The circuit finishes
// the hash over the remaining bytes and then verifies the ECDSA signature.
//
// Tampering with `partial_sha_state` or `signing_input_tail` produces a digest
// that no longer matches the issuer's signature, so verify_signature fails.
fn main(
    pubkey_x: pub [u8; 32],
    pubkey_y: pub [u8; 32],
    signature: [u8; 64],
    // SHA-256 intermediate state after hashing the first K*64 bytes off-circuit.
    // Equals the SHA-256 IV when K == 0.
    partial_sha_state: [u32; 8],
    // Bytes after the precomputed cutoff, 0-padded to MAX_REMAINING.
    signing_input_tail: [u8; MAX_REMAINING],
    // Real (unpadded) byte count of signing_input_tail.
    signing_input_tail_len: u64,
    // Total byte count of the original signing input.
    signing_input_total_len: u64,
) {
    let message_hash = partial_sha256_var_end(
        partial_sha_state,
        signing_input_tail,
        signing_input_tail_len,
        signing_input_total_len,
    );
    assert(ecdsa_secp256r1::verify_signature(
        pubkey_x,
        pubkey_y,
        signature,
        message_hash,
    ));
}
