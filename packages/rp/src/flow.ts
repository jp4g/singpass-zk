import { isReady } from "@singpass-zk/driver/src/health.ts";
import {
  loadRpPrivateJwks,
  pickByUse,
  type Jwks,
} from "@singpass-zk/driver/src/keys.ts";
import { Endpoints, CLIENT_ID } from "./config.ts";
import { makePkce } from "./pkce.ts";
import { randomNonceOrState } from "./state.ts";
import { newDpopKeyset, signDpopProof } from "./dpop.ts";
import { signClientAssertion } from "./assertion.ts";
import { pushAuthorizationRequest } from "./par.ts";
import { walkAuth } from "./authcode.ts";
import { exchangeCode } from "./token.ts";
import { decryptAndVerify, type VerifiedIdToken } from "./jose.ts";

// Drives a full Singpass-style FAPI OIDC flow against MockPass and returns
// the decrypted + verified ID token. The caller is responsible for ensuring
// MockPass is reachable (use `isMockpassReady` to check).
export async function runOidcFlow(): Promise<VerifiedIdToken> {
  const rpPrivate = await loadRpPrivateJwks();
  const rpSig = pickByUse(rpPrivate, "sig");
  const rpEnc = pickByUse(rpPrivate, "enc");

  const discovery = (await fetch(Endpoints.discovery).then((r) =>
    r.json(),
  )) as { issuer: string };
  const issuer = discovery.issuer;
  const jwks = (await fetch(Endpoints.jwks).then((r) => r.json())) as Jwks;

  const pkce = makePkce();
  const state = randomNonceOrState();
  const nonce = randomNonceOrState();
  const dpop = await newDpopKeyset();

  const parAssertion = await signClientAssertion(rpSig, CLIENT_ID, issuer);
  const parDpop = await signDpopProof(dpop, "POST", Endpoints.par);
  const { request_uri } = await pushAuthorizationRequest({
    clientAssertion: parAssertion,
    dpopProof: parDpop,
    codeChallenge: pkce.challenge,
    state,
    nonce,
  });

  const { code, state: returnedState } = await walkAuth(request_uri);
  if (returnedState !== state) {
    throw new Error(
      `state mismatch: expected ${state}, got ${returnedState}`,
    );
  }

  const tokenAssertion = await signClientAssertion(rpSig, CLIENT_ID, issuer);
  const tokenDpop = await signDpopProof(dpop, "POST", Endpoints.token);
  const tokenRes = await exchangeCode({
    code,
    codeVerifier: pkce.verifier,
    clientAssertion: tokenAssertion,
    dpopProof: tokenDpop,
  });

  return decryptAndVerify(tokenRes.id_token, rpEnc, jwks);
}

export async function isMockpassReady(): Promise<boolean> {
  return isReady();
}
