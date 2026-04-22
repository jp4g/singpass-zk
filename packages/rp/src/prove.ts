import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { REPO_ROOT, OUT_DIR } from "@singpass-zk/driver/src/paths.ts";
import {
  MAX_SIGNING_INPUT,
  MAX_ISS_LEN,
  MAX_AUD_LEN,
  MAX_NONCE_LEN,
} from "./dump.ts";

const CIRCUIT_JSON = resolve(REPO_ROOT, "circuit/target/singpass_zk.json");
const MAX_SUB_LEN = 64;

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

  console.log("5. Check sub + exp outputs match payload");
  checkOutputs(publicInputs, expected, meta);
  console.log("   sub and exp match");

  await api.destroy();
  process.exit(ok ? 0 : 1);
}

// Public inputs (in declaration order):
//   pubkey_x          : [u8; 32]                  — 32
//   pubkey_y          : [u8; 32]                  — 32
//   expected_iss      : BoundedVec<u8, 64>        — 65
//   expected_aud      : BoundedVec<u8, 64>        — 65
//   expected_nonce    : BoundedVec<u8, 64>        — 65
//   now               : u64                       — 1
//   Claims return:
//     sub : BoundedVec<u8, 64>                    — 65
//     exp : u64                                   — 1
// Total: 32 + 32 + 65*3 + 1 + 65 + 1 = 326.
function checkOutputs(
  publicInputs: readonly string[],
  expected: PayloadClaims,
  meta: SigningInputMeta,
): void {
  const EXPECTED_COUNT =
    32 + 32 + (MAX_ISS_LEN + 1) + (MAX_AUD_LEN + 1) + (MAX_NONCE_LEN + 1) + 1 + (MAX_SUB_LEN + 1) + 1;
  if (publicInputs.length !== EXPECTED_COUNT) {
    throw new Error(
      `public input count ${publicInputs.length} != expected ${EXPECTED_COUNT}`,
    );
  }

  let off = 0;
  off += 32; // pubkey_x
  off += 32; // pubkey_y
  off += MAX_ISS_LEN + 1;
  off += MAX_AUD_LEN + 1;
  off += MAX_NONCE_LEN + 1;
  off += 1; // now

  const sub = decodeBV(publicInputs, off, MAX_SUB_LEN);
  off += MAX_SUB_LEN + 1;
  const exp = Number(BigInt(publicInputs[off] ?? "0"));

  const encExpected = new TextEncoder().encode(expected.sub);
  for (let i = 0; i < encExpected.length; i++) {
    if (sub.storage[i] !== encExpected[i]) {
      throw new Error(`sub[${i}] mismatch`);
    }
  }
  if (sub.len !== encExpected.length)
    throw new Error(`sub_len ${sub.len} != ${encExpected.length}`);

  if (exp !== expected.exp)
    throw new Error(`exp ${exp} != ${expected.exp}`);
  if (exp <= meta.now)
    throw new Error(`exp ${exp} <= now ${meta.now} (shouldn't have verified!)`);

  console.log(`   sub = "${expected.sub}"`);
  console.log(`   exp = ${expected.exp} (now=${meta.now}, diff=${expected.exp - meta.now}s)`);
}

function decodeBV(
  publicInputs: readonly string[],
  offset: number,
  maxLen: number,
): { storage: Uint8Array; len: number } {
  const storageFields = publicInputs.slice(offset, offset + maxLen);
  const storage = fieldsToBytes(storageFields);
  const len = Number(BigInt(publicInputs[offset + maxLen] ?? "0"));
  return { storage, len };
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
