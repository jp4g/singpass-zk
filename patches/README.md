# Patches applied to `deps/mockpass`

`deps/mockpass` is a git submodule pointing at upstream opengovsg/mockpass.
Edits made directly in the submodule are lost on `git submodule update`.
Patches here are applied automatically by `scripts/apply-patches.sh` (run by
`bun run mockpass:install`) and by `Dockerfile.mockpass`.

Patches apply in alphabetical order. Use a `NN-` prefix when a patch's
context depends on a previous one.

## Current patches

### `01-mockpass-iat-floor.patch`

MockPass's FAPI `id_token` emits `iat` as a float (`Date.now() / 1000`) while
`exp` on the line above uses `Math.floor`. Production Singpass per
[the developer docs](https://docs.developer.singpass.gov.sg/docs/technical-specifications/singpass-authentication-api/2.-token-endpoint/authorization-code-grant)
emits integer timestamps. Our in-circuit JSON parser's scanner cannot tokenize
numbers containing `.`, so the float `iat` breaks parsing.

This patch adds the missing `Math.floor` so MockPass tokens match production
format.

**Upstream status:** should be PR'd to opengovsg/mockpass. Remove this patch
once merged.

### `02-mockpass-cnf-jkt.patch`

MockPass validates the DPoP proof on `/token` and stores the JWK thumbprint
during PAR (`authRequest.dpopJkt`), but never echoes it into the issued
`id_token`. RFC 9449 / FAPI 2.0 specifies a `cnf: { jkt }` claim binding the
token to the holder's DPoP key; without it, downstream verifiers can't
require fresh holder-of-key proof.

This patch adds `cnf: { jkt: authRequest.dpopJkt }` to the `id_token` payload
in `generateIdToken`. Depends on `01-mockpass-iat-floor.patch` already being
applied (its hunk context includes the `Math.floor`-d `iat` line).

**Upstream status:** worth a separate PR to opengovsg/mockpass for FAPI
spec compliance. Remove this patch once merged.
