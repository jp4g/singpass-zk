import { readFile } from "node:fs/promises";
import { RP_PRIVATE_JWKS, RP_PUBLIC_JWKS, ASP_PUBLIC_JWKS } from "./paths.ts";

export type Jwk = {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  alg?: string;
  kid?: string;
  use?: "sig" | "enc";
  [k: string]: unknown;
};

export type Jwks = { keys: Jwk[] };

async function readJwks(path: string): Promise<Jwks> {
  const raw = await readFile(path, "utf8");
  return JSON.parse(raw) as Jwks;
}

export async function loadRpPrivateJwks(): Promise<Jwks> {
  return readJwks(RP_PRIVATE_JWKS);
}

export async function loadRpPublicJwks(): Promise<Jwks> {
  return readJwks(RP_PUBLIC_JWKS);
}

export async function loadAspPublicJwks(): Promise<Jwks> {
  return readJwks(ASP_PUBLIC_JWKS);
}

export function pickByUse(jwks: Jwks, use: "sig" | "enc"): Jwk {
  const k = jwks.keys.find((j) => j.use === use);
  if (!k) throw new Error(`No JWK with use=${use} found`);
  return k;
}
