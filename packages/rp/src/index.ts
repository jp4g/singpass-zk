import { isReady } from "@singpass-zk/driver/src/health.ts";
import {
  loadRpPrivateJwks,
  pickByUse,
} from "@singpass-zk/driver/src/keys.ts";
import type { Jwks } from "@singpass-zk/driver/src/keys.ts";
import { Endpoints, CLIENT_ID, MOCK_NRIC, MOCK_UUID } from "./config.ts";
import { makePkce } from "./pkce.ts";
import { randomNonceOrState } from "./state.ts";
import { newDpopKeyset, signDpopProof } from "./dpop.ts";
import { signClientAssertion } from "./assertion.ts";
import { pushAuthorizationRequest } from "./par.ts";
import { walkAuth } from "./authcode.ts";
import { exchangeCode } from "./token.ts";
import { decryptAndVerify } from "./jose.ts";
import { dumpAll } from "./dump.ts";

async function main() {
  if (!(await isReady())) {
    console.error("MockPass is not responding. Run `bun run driver:up` first.");
    process.exit(1);
  }

  const rpPrivate = await loadRpPrivateJwks();
  const rpSig = pickByUse(rpPrivate, "sig");
  const rpEnc = pickByUse(rpPrivate, "enc");

  // Discover issuer + JWKS.
  const discovery = await fetch(Endpoints.discovery).then((r) => r.json() as Promise<{
    issuer: string;
  }>);
  const issuer = discovery.issuer;
  const jwks = (await fetch(Endpoints.jwks).then((r) => r.json())) as Jwks;

  const pkce = makePkce();
  const state = randomNonceOrState();
  const nonce = randomNonceOrState();
  const dpop = await newDpopKeyset();

  console.log("1. PAR");
  const parAssertion = await signClientAssertion(rpSig, CLIENT_ID, issuer);
  const parDpop = await signDpopProof(dpop, "POST", Endpoints.par);
  const { request_uri } = await pushAuthorizationRequest({
    clientAssertion: parAssertion,
    dpopProof: parDpop,
    codeChallenge: pkce.challenge,
    state,
    nonce,
  });
  console.log(`   request_uri=${request_uri}`);

  console.log(`2. /auth/custom-profile  nric=${MOCK_NRIC} uuid=${MOCK_UUID}`);
  const { code, state: returnedState } = await walkAuth(request_uri);
  if (returnedState !== state) {
    throw new Error(
      `state mismatch: expected ${state}, got ${returnedState}`,
    );
  }
  console.log(`   code=${code.slice(0, 10)}...`);

  console.log("3. /token");
  const tokenAssertion = await signClientAssertion(rpSig, CLIENT_ID, issuer);
  const tokenDpop = await signDpopProof(dpop, "POST", Endpoints.token);
  const tokenRes = await exchangeCode({
    code,
    codeVerifier: pkce.verifier,
    clientAssertion: tokenAssertion,
    dpopProof: tokenDpop,
  });
  console.log(`   id_token (JWE): ${tokenRes.id_token.slice(0, 48)}...`);

  console.log("4. Decrypt + verify inner JWS");
  const verified = await decryptAndVerify(tokenRes.id_token, rpEnc, jwks);
  console.log(`   verified off-circuit. alg=${verified.header["alg"]} kid=${verified.header["kid"]}`);
  console.log(`   payload.sub=${String(verified.payload["sub"])}`);
  console.log(`   payload.iss=${String(verified.payload["iss"])}`);

  console.log("5. Dumping artifacts");
  const files = await dumpAll(verified);
  for (const f of files) console.log(`   wrote ${f}`);

  printNextSteps();
}

function printNextSteps() {
  console.log(`
====================================================================
NEXT STEPS — Noir circuit inputs ready in ./out

circuit/src/main.nr input shape (Phase 1 — SHA-256 off-circuit):

  pubkey_x:     [u8; 32]    public    pubkey.x.hex
  pubkey_y:     [u8; 32]    public    pubkey.y.hex
  message_hash: [u8; 32]    public    signing_input.hash.hex
  signature:    [u8; 64]    private   signature.64.hex

To prove:

  cp out/Prover.toml circuit/Prover.toml
  bun run circuit:execute      # or: cd circuit && nargo execute
  bun run rp:prove             # noir_js witcalc + bb.js prove + verify

Known gaps (see plan file for roadmap):

  - SHA-256 is computed off-circuit → prover-trust gap on the hash.
    Closing this requires pulling the signing input into the circuit
    (partial-SHA or full-SHA) and recomputing the digest there.

  - No claim parsing (iss / aud / exp / nonce not checked).

  - No nullifier — proofs are currently replayable.

  - Single hardcoded issuer key (by kid).

  - MockPass keys differ from production Singpass.
====================================================================
`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
