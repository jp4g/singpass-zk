import {
  SingpassProver,
  parsePublicOutputs,
  type ProveResult,
  type VerifiedIdToken,
} from "@singpass-zk/rp/browser";
import type { CompiledCircuit } from "@noir-lang/noir_js";

export type BenchOpts = {
  circuit: CompiledCircuit;
  verified: VerifiedIdToken;
  iterations: number;
  threads: number;
  log: (line: string) => void;
};

export type BenchTimings = {
  coldInitMs: number;
  witnessMs: number[];
  proofMs: number[];
  verifyMs: number[];
  totalMs: number;
};

export type BenchResult = {
  timings: BenchTimings;
  lastProof: ProveResult & { verified: boolean };
};

export async function runBenchmark(opts: BenchOpts): Promise<BenchResult> {
  const { circuit, verified, iterations, threads, log } = opts;
  const totalStart = performance.now();

  log(`cold init (threads=${threads})…`);
  const coldStart = performance.now();
  const prover = await SingpassProver.create(circuit, { threads });
  const coldInitMs = performance.now() - coldStart;
  log(`  cold init: ${coldInitMs.toFixed(0)} ms`);

  const witnessMs: number[] = [];
  const proofMs: number[] = [];
  const verifyMs: number[] = [];
  let lastProof: (ProveResult & { verified: boolean }) | null = null;

  try {
    for (let i = 1; i <= iterations; i++) {
      log(`iter ${i}/${iterations}`);

      const wStart = performance.now();
      const { witness } = await prover.executeWitness(verified);
      const wMs = performance.now() - wStart;
      witnessMs.push(wMs);
      log(`  witness: ${wMs.toFixed(0)} ms`);

      const pStart = performance.now();
      const { proof, publicInputs } =
        await prover.generateProofFromWitness(witness);
      const pMs = performance.now() - pStart;
      proofMs.push(pMs);
      log(`  prove:   ${pMs.toFixed(0)} ms`);

      const vStart = performance.now();
      const verifiedOk = await prover.verifyProof(proof, publicInputs);
      const vMs = performance.now() - vStart;
      verifyMs.push(vMs);
      log(`  verify:  ${vMs.toFixed(0)} ms ${verifiedOk ? "OK" : "FAIL"}`);

      lastProof = {
        proof,
        publicInputs,
        publicOutputs: parsePublicOutputs(publicInputs),
        verified: verifiedOk,
      };
    }
  } finally {
    await prover.close();
  }

  if (!lastProof) {
    throw new Error("benchmark produced no iterations");
  }

  const totalMs = performance.now() - totalStart;
  log(
    `done. avg witness=${avg(witnessMs).toFixed(0)}ms ` +
      `prove=${avg(proofMs).toFixed(0)}ms ` +
      `verify=${avg(verifyMs).toFixed(0)}ms ` +
      `total=${totalMs.toFixed(0)}ms`,
  );

  return {
    timings: { coldInitMs, witnessMs, proofMs, verifyMs, totalMs },
    lastProof,
  };
}

function avg(xs: number[]): number {
  if (xs.length === 0) return 0;
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}
