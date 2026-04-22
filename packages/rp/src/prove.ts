import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import type { VerifiedIdToken } from "./jose.ts";
import { MAX_SIGNING_INPUT } from "./constants.ts";

// Shape of the witness inputs for circuit/src/main.nr.
export type CircuitInputs = {
  pubkey_x: number[];
  pubkey_y: number[];
  signature: number[];
  signing_input: number[];
  signing_input_len: string;
  header_b64_len: string;
};

export type PublicOutputs = {
  keyHash: bigint;
  issAudHash: bigint;
  nullifier: bigint;
  exp: number;
};

export type ProveResult = {
  proof: Uint8Array;
  publicInputs: readonly string[];
  publicOutputs: PublicOutputs;
};

const PUBLIC_OUTPUT_COUNT = 4;

// Build circuit witness inputs from a verified ID token.
export function buildCircuitInputs(v: VerifiedIdToken): CircuitInputs {
  if (v.signingInput.length >= MAX_SIGNING_INPUT) {
    throw new Error(
      `signing_input length ${v.signingInput.length} >= MAX_SIGNING_INPUT ${MAX_SIGNING_INPUT}. ` +
        `Bump MAX_SIGNING_INPUT in circuit/src/constants.nr and packages/rp/src/constants.ts.`,
    );
  }
  if (v.pubX.length !== 32 || v.pubY.length !== 32) {
    throw new Error("pubkey coords must be 32 bytes each");
  }
  if (v.signature64.length !== 64) {
    throw new Error("signature must be 64 bytes");
  }

  const padded = new Uint8Array(MAX_SIGNING_INPUT);
  padded.set(v.signingInput, 0);

  return {
    pubkey_x: Array.from(v.pubX),
    pubkey_y: Array.from(v.pubY),
    signature: Array.from(v.signature64),
    signing_input: Array.from(padded),
    signing_input_len: String(v.signingInput.length),
    header_b64_len: String(v.jws.header.length),
  };
}

export function parsePublicOutputs(
  publicInputs: readonly string[],
): PublicOutputs {
  if (publicInputs.length !== PUBLIC_OUTPUT_COUNT) {
    throw new Error(
      `expected ${PUBLIC_OUTPUT_COUNT} public outputs, got ${publicInputs.length}`,
    );
  }
  return {
    keyHash: BigInt(publicInputs[0] ?? "0"),
    issAudHash: BigInt(publicInputs[1] ?? "0"),
    nullifier: BigInt(publicInputs[2] ?? "0"),
    exp: Number(BigInt(publicInputs[3] ?? "0")),
  };
}

// Holds a long-lived Noir runtime + Barretenberg backend so callers can run
// many prove / verify operations without paying the bb.js startup cost each
// time. Also sidesteps a socket race where spinning up a fresh Barretenberg
// immediately after `destroy()` can time out waiting for the new socket.
export class SingpassProver {
  private readonly noir: Noir;
  private readonly api: Barretenberg;
  private readonly backend: UltraHonkBackend;
  private closed = false;

  private constructor(
    noir: Noir,
    api: Barretenberg,
    backend: UltraHonkBackend,
  ) {
    this.noir = noir;
    this.api = api;
    this.backend = backend;
  }

  static async create(
    circuit: CompiledCircuit,
    opts: { threads?: number } = {},
  ): Promise<SingpassProver> {
    const noir = new Noir(circuit);
    const api = await Barretenberg.new({ threads: opts.threads ?? 8 });
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    return new SingpassProver(noir, api, backend);
  }

  // Convenience: full prove path. Use the split methods below if you want
  // to time witness gen separately from proof gen (e.g. in benchmarks).
  async prove(verified: VerifiedIdToken): Promise<ProveResult> {
    this.assertOpen();
    const { witness } = await this.executeWitness(verified);
    const { proof, publicInputs } = await this.generateProofFromWitness(witness);
    return {
      proof,
      publicInputs,
      publicOutputs: parsePublicOutputs(publicInputs),
    };
  }

  async executeWitness(
    verified: VerifiedIdToken,
  ): Promise<{ witness: Uint8Array; inputs: CircuitInputs }> {
    this.assertOpen();
    const inputs = buildCircuitInputs(verified);
    const { witness } = await this.noir.execute(inputs);
    return { witness, inputs };
  }

  async generateProofFromWitness(
    witness: Uint8Array,
  ): Promise<{ proof: Uint8Array; publicInputs: readonly string[] }> {
    this.assertOpen();
    return this.backend.generateProof(witness);
  }

  async verifyProof(
    proof: Uint8Array,
    publicInputs: readonly string[],
  ): Promise<boolean> {
    this.assertOpen();
    return this.backend.verifyProof({ proof, publicInputs });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.api.destroy();
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new Error("SingpassProver: already closed");
    }
  }
}
