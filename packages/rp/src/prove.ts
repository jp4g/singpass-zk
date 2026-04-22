import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { poseidon2Hash } from "@zkpassport/poseidon2";
import { REPO_ROOT, OUT_DIR } from "@singpass-zk/driver/src/paths.ts";
import {
  MAX_SIGNING_INPUT,
  MAX_ISS_LEN,
  MAX_AUD_LEN,
  MAX_NONCE_LEN,
} from "./dump.ts";

const CIRCUIT_JSON = resolve(REPO_ROOT, "circuit/target/singpass_zk.json");
const MAX_SUB_LEN = 64;
// Matches circuit/src/main.nr: pack_bytes<N> -> [Field; N/31 + 1].
const SUB_PACKED_FIELDS = Math.floor(MAX_SUB_LEN / 31) + 1;       // 3
const NONCE_PACKED_FIELDS = Math.floor(MAX_NONCE_LEN / 31) + 1;   // 3

// Pack a byte array into Field-sized little-endian chunks (31 bytes per Field).
// Mirrors nodash::pack_bytes.
function packBytes(bytes: Uint8Array, maxLen: number): bigint[] {
  const fieldCount = Math.floor(maxLen / 31) + 1;
  const out: bigint[] = new Array(fieldCount).fill(0n);
  for (let i = 0; i < fieldCount; i++) {
    let acc = 0n;
    let mul = 1n;
    for (let j = 0; j < 31; j++) {
      const idx = i * 31 + j;
      const byte = idx < maxLen && idx < bytes.length ? bytes[idx] ?? 0 : 0;
      acc += BigInt(byte) * mul;
      mul *= 256n;
    }
    out[i] = acc;
  }
  return out;
}

// poseidon2(pack(pubkey_x || pubkey_y)). Mirrors circuit compute_key_hash.
function expectedKeyHash(x: Uint8Array, y: Uint8Array): bigint {
  if (x.length !== 32 || y.length !== 32) {
    throw new Error("pubkey coords must be 32 bytes each");
  }
  const concat = new Uint8Array(64);
  concat.set(x, 0);
  concat.set(y, 32);
  const packed = packBytes(concat, 64);
  return poseidon2Hash(packed);
}

// poseidon2(sub_packed || sub_len || nonce_packed || nonce_len)
// Mirrors circuit/src/main.nr:compute_nullifier.
function expectedNullifier(
  sub: Uint8Array,
  subLen: number,
  nonce: Uint8Array,
  nonceLen: number,
): bigint {
  const subZero = new Uint8Array(MAX_SUB_LEN);
  subZero.set(sub.subarray(0, subLen), 0);
  const nonceZero = new Uint8Array(MAX_NONCE_LEN);
  nonceZero.set(nonce.subarray(0, nonceLen), 0);

  const subPacked = packBytes(subZero, MAX_SUB_LEN);
  const noncePacked = packBytes(nonceZero, MAX_NONCE_LEN);

  const preimage: bigint[] = [
    ...subPacked,
    BigInt(subLen),
    ...noncePacked,
    BigInt(nonceLen),
  ];
  return poseidon2Hash(preimage);
}

async function readHex(name: string): Promise<number[]> {
  const hex = (await readFile(resolve(OUT_DIR, name), "utf8")).trim();
  if (hex.length % 2 !== 0) {
    throw new Error(`${name}: odd hex length ${hex.length}`);
  }
  const out = new Array<number>(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function readBytes(name: string): Promise<Uint8Array> {
  return new Uint8Array(await readFile(resolve(OUT_DIR, name)));
}

async function readJson<T>(name: string): Promise<T> {
  const raw = await readFile(resolve(OUT_DIR, name), "utf8");
  return JSON.parse(raw) as T;
}

async function requireCompiledCircuit(): Promise<CompiledCircuit> {
  if (!existsSync(CIRCUIT_JSON)) {
    console.error(`No compiled circuit at ${CIRCUIT_JSON}`);
    console.error(`Run: bun run circuit:execute`);
    process.exit(1);
  }
  const raw = await readFile(CIRCUIT_JSON, "utf8");
  return JSON.parse(raw) as CompiledCircuit;
}

function fieldsToBytes(fields: readonly string[]): Uint8Array {
  const out = new Uint8Array(fields.length);
  for (let i = 0; i < fields.length; i++) {
    out[i] = Number(BigInt(fields[i] ?? "0") & 0xffn);
  }
  return out;
}

type PayloadClaims = {
  iss: string;
  aud: string;
  exp: number;
  nonce: string;
  sub: string;
};

type BoundedVecJson = { storage: number[]; len: number };

type SigningInputMeta = {
  signing_input_len: number;
  header_b64_len: number;
  payload_b64_len: number;
  expected_iss: BoundedVecJson;
  expected_aud: BoundedVecJson;
  expected_nonce: BoundedVecJson;
  now: number;
};

async function main() {
  const circuit = await requireCompiledCircuit();

  const pubkey_x = await readHex("pubkey.x.hex");
  const pubkey_y = await readHex("pubkey.y.hex");
  const signature = await readHex("signature.64.hex");
  const signing_input = await readBytes("signing_input.padded.bin");
  const meta = await readJson<SigningInputMeta>("signing_input.meta.json");
  const expected = await readJson<PayloadClaims>("jws.payload.json");

  if (pubkey_x.length !== 32) throw new Error("pubkey_x must be 32 bytes");
  if (pubkey_y.length !== 32) throw new Error("pubkey_y must be 32 bytes");
  if (signature.length !== 64) throw new Error("signature must be 64 bytes");
  if (signing_input.length !== MAX_SIGNING_INPUT) {
    throw new Error(
      `signing_input length ${signing_input.length} != ${MAX_SIGNING_INPUT}`,
    );
  }

  const inputs = {
    pubkey_x,
    pubkey_y,
    expected_iss: {
      storage: meta.expected_iss.storage,
      len: meta.expected_iss.len.toString(),
    },
    expected_aud: {
      storage: meta.expected_aud.storage,
      len: meta.expected_aud.len.toString(),
    },
    expected_nonce: {
      storage: meta.expected_nonce.storage,
      len: meta.expected_nonce.len.toString(),
    },
    now: meta.now.toString(),
    signature,
    signing_input: Array.from(signing_input),
    signing_input_len: meta.signing_input_len.toString(),
    header_b64_len: meta.header_b64_len.toString(),
  };

  console.log("1. Witness generation (noir_js)");
  console.log(
    `   signing_input_len=${meta.signing_input_len}  header_b64_len=${meta.header_b64_len}  now=${meta.now}`,
  );
  const noir = new Noir(circuit);
  const tWit = performance.now();
  const { witness } = await noir.execute(inputs);
  console.log(`   witness solved in ${((performance.now() - tWit) / 1000).toFixed(2)}s`);

  console.log("2. Backend init (UltraHonk)");
  const api = await Barretenberg.new({ threads: 8 });
  const backend = new UltraHonkBackend(circuit.bytecode, api);

  console.log("3. generateProof");
  const tProve = performance.now();
  const { proof, publicInputs } = await backend.generateProof(witness);
  console.log(
    `   proof generated in ${((performance.now() - tProve) / 1000).toFixed(2)}s  ` +
      `(${proof.length} bytes, ${publicInputs.length} public inputs)`,
  );

  console.log("4. verifyProof");
  const tVerify = performance.now();
  const ok = await backend.verifyProof({ proof, publicInputs });
  console.log(
    `   verification ${ok ? "OK" : "FAILED"} in ${(
      (performance.now() - tVerify) /
      1000
    ).toFixed(2)}s`,
  );

  console.log("5. Check key_hash + nullifier + exp outputs match expected");
  checkOutputs(
    publicInputs,
    expected,
    meta,
    Uint8Array.from(pubkey_x),
    Uint8Array.from(pubkey_y),
  );

  await api.destroy();
  process.exit(ok ? 0 : 1);
}

// Public inputs (in declaration order):
//   expected_iss    : BoundedVec<u8, 64>      — 65
//   expected_aud    : BoundedVec<u8, 64>      — 65
//   expected_nonce  : BoundedVec<u8, 64>      — 65
//   now             : u64                     — 1
//   Claims return:
//     key_hash  : Field                       — 1
//     nullifier : Field                       — 1
//     exp       : u64                         — 1
// Total: 65*3 + 1 + 1 + 1 + 1 = 199.
function checkOutputs(
  publicInputs: readonly string[],
  expected: PayloadClaims,
  meta: SigningInputMeta,
  pubkeyX: Uint8Array,
  pubkeyY: Uint8Array,
): void {
  const EXPECTED_COUNT =
    (MAX_ISS_LEN + 1) + (MAX_AUD_LEN + 1) + (MAX_NONCE_LEN + 1) + 1 + 1 + 1 + 1;
  if (publicInputs.length !== EXPECTED_COUNT) {
    throw new Error(
      `public input count ${publicInputs.length} != expected ${EXPECTED_COUNT}`,
    );
  }

  let off = 0;
  off += MAX_ISS_LEN + 1;
  off += MAX_AUD_LEN + 1;
  off += MAX_NONCE_LEN + 1;
  off += 1; // now

  const keyHash = BigInt(publicInputs[off] ?? "0");
  off += 1;
  const nullifier = BigInt(publicInputs[off] ?? "0");
  off += 1;
  const exp = Number(BigInt(publicInputs[off] ?? "0"));

  const expectedK = expectedKeyHash(pubkeyX, pubkeyY);
  if (keyHash !== expectedK) {
    throw new Error(
      `key_hash mismatch:\n  circuit:  0x${keyHash.toString(16)}\n  expected: 0x${expectedK.toString(16)}`,
    );
  }

  const nonceBytes = new TextEncoder().encode(expected.nonce);
  const subBytes = new TextEncoder().encode(expected.sub);
  const expectedN = expectedNullifier(subBytes, subBytes.length, nonceBytes, nonceBytes.length);
  if (nullifier !== expectedN) {
    throw new Error(
      `nullifier mismatch:\n  circuit:  0x${nullifier.toString(16)}\n  expected: 0x${expectedN.toString(16)}`,
    );
  }

  if (exp !== expected.exp) throw new Error(`exp ${exp} != ${expected.exp}`);
  if (exp <= meta.now) throw new Error(`exp <= now - shouldn't have verified`);

  console.log(`   key_hash  = 0x${keyHash.toString(16)}`);
  console.log(`   nullifier = 0x${nullifier.toString(16)}`);
  console.log(`   exp       = ${expected.exp} (now=${meta.now}, diff=${expected.exp - meta.now}s)`);
  console.log(`   (both hashes recomputed off-circuit; match)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
