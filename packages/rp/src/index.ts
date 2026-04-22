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

circuit/src/main.nr input shape (Phase 2 — SHA-256 computed in-circuit):

  pubkey_x:               [u8; 32]    public    pubkey.x.hex
  pubkey_y:               [u8; 32]    public    pubkey.y.hex
  signature:              [u8; 64]    private   signature.64.hex
  partial_sha_state:      [u32; 8]    private   partial_sha.state.json
  signing_input_tail:     [u8; 256]   private   signing_input.tail.padded.bin
  signing_input_tail_len: u64         private   partial_sha.state.json (tail_len)
  signing_input_total_len:u64         private   partial_sha.state.json (total_len)

The circuit reconstructs the SHA-256 digest from partial_sha_state + the tail,
then verifies the P-256 ECDSA signature over that digest.

To prove:

  cp out/Prover.toml circuit/Prover.toml
  bun run circuit:execute      # or: cd circuit && nargo execute
  bun run rp:prove             # noir_js witcalc + bb.js prove + verify

Scope boundaries remaining (see plan file for phase roadmap):

  - No claim parsing (iss / aud / exp / nonce not checked).
    Payload values are in out/jws.payload.json for reference.

  - No nullifier — proofs are currently replayable.

  - Single hardcoded issuer key (by kid). Production needs a committed
    JWKS and in-circuit kid selection.

  - MockPass keys differ from production Singpass. Swap to production by
    pointing at https://id.singpass.gov.sg/.well-known/keys and
    redeploying with the production pubkey.
====================================================================
`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
