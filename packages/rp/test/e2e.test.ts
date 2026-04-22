import { test, expect, beforeAll, afterAll } from "bun:test";
import {
  runOidcFlow,
  isMockpassReady,
  loadCompiledCircuit,
  SingpassProver,
  expectedKeyHash,
  expectedIssAudHash,
  expectedNullifier,
} from "../src";

let prover: SingpassProver;

beforeAll(async () => {
  if (!(await isMockpassReady())) {
    throw new Error(
      "MockPass is not responding. Run `bun run driver:up` first.",
    );
  }
  const circuit = await loadCompiledCircuit();
  prover = await SingpassProver.create(circuit);
});

afterAll(async () => {
  await prover?.close();
});

test(
  "e2e: OIDC flow -> witness -> UltraHonk prove -> verify -> outputs match oracle",
  async () => {
    const verified = await runOidcFlow();
    const payload = verified.payload as {
      iss: string;
      aud: string;
      exp: number;
      nonce: string;
      sub: string;
    };

    const { proof, publicInputs, publicOutputs } = await prover.prove(verified);
    expect(proof.byteLength).toBeGreaterThan(0);
    expect(publicInputs).toHaveLength(4);

    expect(await prover.verifyProof(proof, publicInputs)).toBe(true);

    expect(publicOutputs.keyHash).toBe(
      expectedKeyHash(verified.pubX, verified.pubY),
    );
    expect(publicOutputs.issAudHash).toBe(
      expectedIssAudHash(payload.iss, payload.aud),
    );
    expect(publicOutputs.nullifier).toBe(
      expectedNullifier(payload.sub, payload.nonce),
    );
    expect(publicOutputs.exp).toBe(payload.exp);
    expect(publicOutputs.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  },
  { timeout: 120_000 },
);
