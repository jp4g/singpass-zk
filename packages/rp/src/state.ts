import { randomBytes } from "node:crypto";
import { b64urlEncode } from "./b64.ts";

// MockPass requires /^[A-Za-z0-9/+_\-=.]{30,255}$/ for state and nonce.
// base64url of 32 bytes = 43 chars, satisfies the rule.
export function randomNonceOrState(): string {
  return b64urlEncode(randomBytes(32));
}
