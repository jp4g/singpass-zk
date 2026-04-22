use std::ecdsa_secp256r1;

// Verify a Singpass OIDC ID token's inner JWS signature.
//
// PROVER TRUST GAP: the SHA-256 digest is computed OFF-circuit by the RP and
// passed in as `message_hash`. A malicious prover could substitute any hash
// they hold a matching signature for. Closing this gap is the next phase
// (claim extraction over the raw signing input inside the circuit).
fn main(
    pubkey_x: pub [u8; 32],
    pubkey_y: pub [u8; 32],
    message_hash: pub [u8; 32],
    signature: [u8; 64],
) {
    assert(ecdsa_secp256r1::verify_signature(
        pubkey_x,
        pubkey_y,
        signature,
        message_hash,
    ));
}
