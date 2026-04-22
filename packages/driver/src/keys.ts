import { readFile } from "node:fs/promises";
import { RP_PRIVATE_JWKS } from "./paths.ts";

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

export async function loadRpPrivateJwks(): Promise<Jwks> {
  const raw = await readFile(RP_PRIVATE_JWKS, "utf8");
  return JSON.parse(raw) as Jwks;
}

export function pickByUse(jwks: Jwks, use: "sig" | "enc"): Jwk {
  const k = jwks.keys.find((j) => j.use === use);
  if (!k) throw new Error(`No JWK with use=${use} found`);
  return k;
}
