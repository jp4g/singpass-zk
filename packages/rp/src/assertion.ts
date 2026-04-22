import { SignJWT, importJWK } from "jose";
import { randomUUID } from "node:crypto";
import type { Jwk } from "@singpass-zk/driver/src/keys.ts";

export async function signClientAssertion(
  rpSigningJwk: Jwk,
  clientId: string,
  audience: string,
): Promise<string> {
  const key = await importJWK(rpSigningJwk, "ES256");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({
      alg: "ES256",
      kid: rpSigningJwk.kid,
      typ: "JWT",
    })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audience)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 120)
    .sign(key);
}

export const CLIENT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
