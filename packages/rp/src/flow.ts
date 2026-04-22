import { createHash, randomBytes } from "node:crypto";
import { isReady } from "@singpass-zk/driver/src/health.ts";
import {
  loadRpPrivateJwks,
  pickByUse,
  type Jwks,
} from "@singpass-zk/driver/src/keys.ts";
import { Endpoints, CLIENT_ID } from "./config.ts";
import { b64urlEncode } from "./b64.ts";
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

  const discovery = await fetchJson<{ issuer: string }>(Endpoints.discovery);
  const jwks = await fetchJson<Jwks>(Endpoints.jwks);
  const issuer = discovery.issuer;

  // PKCE: 64 bytes -> 86-char base64url verifier (well within RFC 7636's
  // 43-128 range). state/nonce: 32 bytes -> 43 chars, satisfies MockPass's
  // /^[A-Za-z0-9/+_\-=.]{30,255}$/ rule.
  const verifier = b64urlEncode(randomBytes(64));
  const challenge = b64urlEncode(createHash("sha256").update(verifier).digest());
  const state = b64urlEncode(randomBytes(32));
  const nonce = b64urlEncode(randomBytes(32));
  const dpop = await newDpopKeyset();

  const parAssertion = await signClientAssertion(rpSig, CLIENT_ID, issuer);
  const parDpop = await signDpopProof(dpop, "POST", Endpoints.par);
  const { request_uri } = await pushAuthorizationRequest({
    clientAssertion: parAssertion,
    dpopProof: parDpop,
    codeChallenge: challenge,
    state,
    nonce,
  });

  const { code, state: returnedState } = await walkAuth(request_uri);
  if (returnedState !== state) {
    throw new Error(`state mismatch: expected ${state}, got ${returnedState}`);
  }

  const tokenAssertion = await signClientAssertion(rpSig, CLIENT_ID, issuer);
  const tokenDpop = await signDpopProof(dpop, "POST", Endpoints.token);
  const tokenRes = await exchangeCode({
    code,
    codeVerifier: verifier,
    clientAssertion: tokenAssertion,
    dpopProof: tokenDpop,
  });

  return decryptAndVerify(tokenRes.id_token, rpEnc, jwks);
}

export async function isMockpassReady(): Promise<boolean> {
  return isReady();
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`GET ${url} -> ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}
