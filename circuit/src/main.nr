use std::ecdsa_secp256r1;
use json_parser::JSON1kb;
use sha256::sha256_var;
use base64::BASE64_URL_DECODER;
use nodash::pack_bytes;
use poseidon::poseidon2::Poseidon2;

global MAX_SIGNING_INPUT: u32 = 768;
global MAX_PAYLOAD_B64: u32 = 720;
global MAX_PAYLOAD_BYTES: u32 = 540;

global MAX_KEY_LEN: u32 = 16;
global MAX_ISS_LEN: u32 = 64;
global MAX_AUD_LEN: u32 = 64;
global MAX_NONCE_LEN: u32 = 64;
global MAX_SUB_LEN: u32 = 64;

// pack_bytes<N> returns [Field; N/31 + 1].
global SUB_PACKED_FIELDS: u32 = MAX_SUB_LEN / 31 + 1;       // 3
global NONCE_PACKED_FIELDS: u32 = MAX_NONCE_LEN / 31 + 1;   // 3
global ISS_PACKED_FIELDS: u32 = MAX_ISS_LEN / 31 + 1;       // 3
global AUD_PACKED_FIELDS: u32 = MAX_AUD_LEN / 31 + 1;       // 3
global PUBKEY_PACKED_FIELDS: u32 = 64 / 31 + 1;             // 3

// Preimage layouts.
global NULLIFIER_PREIMAGE_LEN: u32 = SUB_PACKED_FIELDS + 1 + NONCE_PACKED_FIELDS + 1;   // 8
global ISS_AUD_PREIMAGE_LEN: u32 = ISS_PACKED_FIELDS + 1 + AUD_PACKED_FIELDS + 1;       // 8

// Public outputs:
//   key_hash      - poseidon2 over packed pubkey bytes. Verifier matches against
//                   known Singpass pubkey hash(es) to reject unrelated signers.
//   iss_aud_hash  - poseidon2 over (iss, aud) so the verifier can pin to a
//                   specific issuer + client_id pair without spending 130
//                   public inputs per proof.
//   nullifier     - poseidon2 over (sub, nonce); session-scoped identity handle.
//   exp           - token expiry.
pub struct Claims {
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
) -> pub Claims {
    assert(signing_input[header_b64_len] == 0x2E);

    let message_hash: [u8; 32] = sha256_var(signing_input, signing_input_len);

    assert(ecdsa_secp256r1::verify_signature(
        pubkey_x,
        pubkey_y,
        signature,
        message_hash,
    ));

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

    let payload_bv: BoundedVec<u8, MAX_PAYLOAD_BYTES> =
        BASE64_URL_DECODER::decode_var(payload_b64);

    let mut payload: [u8; MAX_PAYLOAD_BYTES] = [0x20; MAX_PAYLOAD_BYTES];
    for i in 0..MAX_PAYLOAD_BYTES {
        if (i as u32) < payload_bv.len() {
            payload[i] = payload_bv.get_unchecked(i);
        }
    }

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

    let key_hash = compute_key_hash(pubkey_x, pubkey_y);
    let iss_aud_hash = compute_iss_aud_hash(iss, aud);
    let nullifier = compute_nullifier(sub, nonce);

    Claims { key_hash, iss_aud_hash, nullifier, exp }
}

fn compute_key_hash(x: [u8; 32], y: [u8; 32]) -> Field {
    let mut concat: [u8; 64] = [0; 64];
    for i in 0..32 {
        concat[i] = x[i];
        concat[32 + i] = y[i];
    }
    let packed: [Field; PUBKEY_PACKED_FIELDS] = pack_bytes(concat);
    Poseidon2::hash(packed, PUBKEY_PACKED_FIELDS)
}

fn compute_iss_aud_hash(
    iss: BoundedVec<u8, MAX_ISS_LEN>,
    aud: BoundedVec<u8, MAX_AUD_LEN>,
) -> Field {
    let iss_bytes: [u8; MAX_ISS_LEN] = bv_to_storage(iss);
    let aud_bytes: [u8; MAX_AUD_LEN] = bv_to_storage(aud);

    let iss_packed: [Field; ISS_PACKED_FIELDS] = pack_bytes(iss_bytes);
    let aud_packed: [Field; AUD_PACKED_FIELDS] = pack_bytes(aud_bytes);

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

fn compute_nullifier(
    sub: BoundedVec<u8, MAX_SUB_LEN>,
    nonce: BoundedVec<u8, MAX_NONCE_LEN>,
) -> Field {
    let sub_bytes: [u8; MAX_SUB_LEN] = bv_to_storage(sub);
    let nonce_bytes: [u8; MAX_NONCE_LEN] = bv_to_storage(nonce);

    let sub_packed: [Field; SUB_PACKED_FIELDS] = pack_bytes(sub_bytes);
    let nonce_packed: [Field; NONCE_PACKED_FIELDS] = pack_bytes(nonce_bytes);

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

fn key_vec<let N: u32>(s: str<N>) -> BoundedVec<u8, MAX_KEY_LEN> {
    let bytes: [u8; N] = s.as_bytes();
    let mut storage: [u8; MAX_KEY_LEN] = [0; MAX_KEY_LEN];
    for i in 0..N {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, N)
}

fn bv_to_storage<let N: u32>(bv: BoundedVec<u8, N>) -> [u8; N] {
    let mut out: [u8; N] = [0; N];
    for i in 0..N {
        if (i as u32) < bv.len() {
            out[i] = bv.get_unchecked(i);
        }
    }
    out
}

