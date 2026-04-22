import { createHash, randomBytes } from "node:crypto";
import { b64urlEncode } from "./b64.ts";

export type Pkce = {
  verifier: string;
  challenge: string;
  method: "S256";
};

export function makePkce(): Pkce {
  // 64 bytes -> 86-char base64url verifier, well within 43-128 range.
  const verifier = b64urlEncode(randomBytes(64));
  const challenge = b64urlEncode(createHash("sha256").update(verifier).digest());
  return { verifier, challenge, method: "S256" };
}
