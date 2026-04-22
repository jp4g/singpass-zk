// Browser-safe subset of the SDK. No imports that touch node:fs / node:crypto
// transitively; safe to bundle into a Vite app.
//
// The full barrel (`./index.ts`) additionally re-exports `runOidcFlow` /
// `isMockpassReady` from `./flow.ts`, which transitively pulls in
// `@singpass-zk/driver/src/keys.ts` (uses `node:fs/promises`) and `./jose.ts`
// (uses `node:crypto`). Those stay server-only.

export {
  SingpassProver,
  buildCircuitInputs,
  parsePublicOutputs,
  type CircuitInputs,
  type ProveResult,
  type PublicOutputs,
} from "./prove.ts";
export {
  expectedKeyHash,
  expectedIssAudHash,
  expectedNullifier,
} from "./hashes.ts";
export type { VerifiedIdToken } from "./jose.ts";
export {
  deserialize,
  type VerifiedIdTokenDto,
} from "./dto.ts";
export {
  MAX_SIGNING_INPUT,
  MAX_ISS_LEN,
  MAX_AUD_LEN,
  MAX_NONCE_LEN,
  MAX_SUB_LEN,
} from "./constants.ts";
