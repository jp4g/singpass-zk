# Patches applied to `deps/mockpass`

`deps/mockpass` is a git submodule pointing at upstream opengovsg/mockpass.
Edits made directly in the submodule are lost on `git submodule update`.
Patches here are applied automatically by `scripts/apply-patches.sh`, which is
invoked by `bun run mockpass:install`.

## Current patches

### `mockpass-iat-floor.patch`

MockPass's FAPI `id_token` emits `iat` as a float (`Date.now() / 1000`) while
`exp` on the line above uses `Math.floor`. Production Singpass per
[the developer docs](https://docs.developer.singpass.gov.sg/docs/technical-specifications/singpass-authentication-api/2.-token-endpoint/authorization-code-grant)
emits integer timestamps. Our in-circuit JSON parser's scanner cannot tokenize
numbers containing `.`, so the float `iat` breaks parsing.

This patch adds the missing `Math.floor` so MockPass tokens match production
format.

**Upstream status:** should be PR'd to opengovsg/mockpass. Remove this patch
once merged.
