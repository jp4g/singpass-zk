import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { REPO_ROOT, OUT_DIR } from "@singpass-zk/driver/src/paths.ts";
import { MAX_PAYLOAD_BYTES } from "./dump.ts";

const CIRCUIT_JSON = resolve(REPO_ROOT, "circuit/target/singpass_zk.json");

// Must mirror the `MAX_*_LEN` globals in circuit/src/main.nr.
const MAX_ISS_LEN = 64;
const MAX_AUD_LEN = 64;
const MAX_NONCE_LEN = 64;
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

// Decode a run of bytes-as-Field-hex-strings into a Uint8Array.
function fieldsToBytes(fields: readonly string[]): Uint8Array {
  const out = new Uint8Array(fields.length);
  for (let i = 0; i < fields.length; i++) {
    // Each field element is a 0x-prefixed hex string; for u8 it fits in one byte.
    out[i] = Number(BigInt(fields[i] ?? "0") & 0xffn);
  }
  return out;
}

// Compare two byte arrays up to `len` of `actual`, and require the remaining
// bytes in `actual` to be zero (padding).
function assertPadded(
  label: string,
  actual: Uint8Array,
  expected: Uint8Array,
): void {
  const n = expected.length;
  if (actual.length < n) {
    throw new Error(
      `${label}: expected ${n} bytes of data but circuit output has capacity ${actual.length}`,
    );
  }
  for (let i = 0; i < n; i++) {
    if (actual[i] !== expected[i]) {
      throw new Error(
        `${label}[${i}] mismatch: expected ${expected[i]?.toString(16)}, got ${actual[i]?.toString(16)}`,
      );
    }
  }
  for (let i = n; i < actual.length; i++) {
    if (actual[i] !== 0) {
      throw new Error(
        `${label} padding at [${i}] should be 0, got ${actual[i]?.toString(16)}`,
      );
    }
  }
}

type PayloadClaims = {
  iss: string;
  aud: string;
  exp: number;
  nonce: string;
  sub: string;
};

async function main() {
  const circuit = await requireCompiledCircuit();

  const pubkey_x = await readHex("pubkey.x.hex");
  const pubkey_y = await readHex("pubkey.y.hex");
  const message_hash = await readHex("signing_input.hash.hex");
  const signature = await readHex("signature.64.hex");
  const paddedPayload = await readBytes("payload.padded.bin");
  const expected = await readJson<PayloadClaims>("jws.payload.json");

  if (pubkey_x.length !== 32) throw new Error("pubkey_x must be 32 bytes");
  if (pubkey_y.length !== 32) throw new Error("pubkey_y must be 32 bytes");
  if (message_hash.length !== 32) throw new Error("message_hash must be 32 bytes");
  if (signature.length !== 64) throw new Error("signature must be 64 bytes");
  if (paddedPayload.length !== MAX_PAYLOAD_BYTES) {
    throw new Error(
      `paddedPayload length ${paddedPayload.length} != ${MAX_PAYLOAD_BYTES}`,
    );
  }

  const inputs = {
    pubkey_x,
    pubkey_y,
    message_hash,
    signature,
    payload: Array.from(paddedPayload),
  };

  console.log("1. Witness generation (noir_js)");
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

  console.log("5. Check extracted claims match payload");
  checkClaims(publicInputs, expected);
  console.log("   all 5 claims match");

  await api.destroy();
  process.exit(ok ? 0 : 1);
}

// Public input layout (from circuit ABI, in declaration order):
//   pubkey_x     : [u8; 32]                   — 32 Fields
//   pubkey_y     : [u8; 32]                   — 32 Fields
//   message_hash : [u8; 32]                   — 32 Fields
//   Claims { iss, aud, exp, nonce, sub } return:
//     iss   : BoundedVec<u8, 64>              — 64 storage + 1 len = 65 Fields
//     aud   : BoundedVec<u8, 64>              — 65 Fields
//     exp   : u64                             — 1 Field
//     nonce : BoundedVec<u8, 64>              — 65 Fields
//     sub   : BoundedVec<u8, 64>              — 65 Fields
// Total: 32 + 32 + 32 + 65*4 + 1 = 357.
function checkClaims(
  publicInputs: readonly string[],
  expected: PayloadClaims,
): void {
  const EXPECTED_PUB_INPUTS =
    32 + 32 + 32 + (MAX_ISS_LEN + 1) + (MAX_AUD_LEN + 1) + 1 + (MAX_NONCE_LEN + 1) + (MAX_SUB_LEN + 1);
  if (publicInputs.length !== EXPECTED_PUB_INPUTS) {
    throw new Error(
      `public input count ${publicInputs.length} != expected ${EXPECTED_PUB_INPUTS}`,
    );
  }

  let off = 96; // skip pubkey_x + pubkey_y + message_hash

  const iss = decodeBoundedVec(publicInputs, off, MAX_ISS_LEN);
  off += MAX_ISS_LEN + 1;
  const aud = decodeBoundedVec(publicInputs, off, MAX_AUD_LEN);
  off += MAX_AUD_LEN + 1;
  const exp = Number(BigInt(publicInputs[off] ?? "0"));
  off += 1;
  const nonce = decodeBoundedVec(publicInputs, off, MAX_NONCE_LEN);
  off += MAX_NONCE_LEN + 1;
  const sub = decodeBoundedVec(publicInputs, off, MAX_SUB_LEN);
  off += MAX_SUB_LEN + 1;

  const enc = new TextEncoder();
  assertPadded("iss", iss.storage, enc.encode(expected.iss));
  assertPadded("aud", aud.storage, enc.encode(expected.aud));
  assertPadded("nonce", nonce.storage, enc.encode(expected.nonce));
  assertPadded("sub", sub.storage, enc.encode(expected.sub));

  if (iss.len !== expected.iss.length)
    throw new Error(`iss_len mismatch: ${iss.len} vs ${expected.iss.length}`);
  if (aud.len !== expected.aud.length)
    throw new Error(`aud_len mismatch: ${aud.len} vs ${expected.aud.length}`);
  if (nonce.len !== expected.nonce.length)
    throw new Error(`nonce_len mismatch: ${nonce.len} vs ${expected.nonce.length}`);
  if (sub.len !== expected.sub.length)
    throw new Error(`sub_len mismatch: ${sub.len} vs ${expected.sub.length}`);
  if (exp !== expected.exp)
    throw new Error(`exp mismatch: ${exp} vs ${expected.exp}`);

  console.log(`   iss   = "${expected.iss}"`);
  console.log(`   aud   = "${expected.aud}"`);
  console.log(`   exp   = ${expected.exp}`);
  console.log(`   nonce = "${expected.nonce}"`);
  console.log(`   sub   = "${expected.sub}"`);
}

function decodeBoundedVec(
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
