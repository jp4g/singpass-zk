import { generateKeyPair, SignJWT, exportJWK, type KeyLike, type JWK } from "jose";
import { randomUUID } from "node:crypto";

export type DpopKeyset = {
  privateKey: KeyLike;
  publicJwk: JWK;
};

export async function newDpopKeyset(): Promise<DpopKeyset> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  return { privateKey, publicJwk };
}

export async function signDpopProof(
  keyset: DpopKeyset,
  htm: "POST" | "GET",
  htu: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    htm,
    htu,
    jti: randomUUID(),
    iat: now,
    exp: now + 120,
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: {
        kty: keyset.publicJwk.kty!,
        crv: keyset.publicJwk.crv!,
        x: keyset.publicJwk.x!,
        y: keyset.publicJwk.y!,
      },
    })
    .sign(keyset.privateKey);
}
