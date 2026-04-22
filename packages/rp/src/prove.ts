import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { REPO_ROOT, OUT_DIR } from "@singpass-zk/driver/src/paths.ts";
import { MAX_PAYLOAD_BYTES } from "./dump.ts";

const CIRCUIT_JSON = resolve(REPO_ROOT, "circuit/target/singpass_zk.json");

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

async function requireCompiledCircuit(): Promise<CompiledCircuit> {
  if (!existsSync(CIRCUIT_JSON)) {
    console.error(`No compiled circuit at ${CIRCUIT_JSON}`);
    console.error(`Run: bun run circuit:execute`);
    process.exit(1);
  }
  const raw = await readFile(CIRCUIT_JSON, "utf8");
  return JSON.parse(raw) as CompiledCircuit;
}

async function main() {
  const circuit = await requireCompiledCircuit();

  const pubkey_x = await readHex("pubkey.x.hex");
  const pubkey_y = await readHex("pubkey.y.hex");
  const message_hash = await readHex("signing_input.hash.hex");
  const signature = await readHex("signature.64.hex");
  const paddedPayload = await readBytes("payload.padded.bin");

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
  const { witness, returnValue } = await noir.execute(inputs);
  console.log(`   witness solved in ${((performance.now() - tWit) / 1000).toFixed(2)}s`);
  console.log(`   claims_digest = ${returnValue}`);

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

  // Public inputs: pubkey_x(32) + pubkey_y(32) + message_hash(32) + claims_digest(1) = 97.
  const expectedPublicInputs = 32 + 32 + 32 + 1;
  if (publicInputs.length !== expectedPublicInputs) {
    console.warn(
      `   WARN: expected ${expectedPublicInputs} public inputs, got ${publicInputs.length}`,
    );
  }

  await api.destroy();
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
