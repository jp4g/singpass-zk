# singpass-zk

Prototype: verify a Singpass OIDC ID token's signature inside a Noir ZK circuit.

## Layout

- `packages/driver` — manages MockPass lifecycle (spawn, health, key loading)
- `packages/rp` — relying party that runs the FAPI flow and dumps Noir-circuit-ready artifacts
- `circuit` — Noir circuit calling `std::ecdsa_secp256r1::verify_signature`
- `deps/mockpass` — git submodule of [opengovsg/mockpass](https://github.com/opengovsg/mockpass)
- `out/` — dump artifacts (gitignored)

## First-time setup

```bash
git submodule update --init --recursive
bun install                  # workspace deps for packages/*
bun run mockpass:install     # npm install inside deps/mockpass
noirup -v 1.0.0-beta.20      # nargo 1.0.0-beta.20 (matches noir_js + bb.js 4.2.0)
```

> Note: scripts call `$HOME/.nargo/bin/nargo` explicitly to sidestep any older
> `nargo` on `PATH` (e.g. the Aztec-installed one).

## Run end-to-end

```bash
bun run driver:up            # MockPass on :5156 (detached)
bun run rp:flow              # PAR → auth → token, decrypt JWE, dump artifacts
cp out/Prover.toml circuit/
bun run circuit:execute      # witness
bun run rp:prove             # noir_js witcalc + bb.js prove + verify (TS)
bun run driver:down          # stop MockPass
```

## Artifacts in `out/`

| File | What |
| - | - |
| `jwe.parts.json` | Raw 5-part compact JWE (base64url) |
| `jws.compact.txt` | Decrypted inner JWS (3-part compact) |
| `jws.header.json` / `jws.payload.json` | Decoded |
| `signing_input.bin` | UTF-8 bytes that get SHA-256'd |
| `signing_input.hash.hex` | 32-byte SHA-256 digest (reference only) |
| `signature.{r,s,64}.hex` | r, s, and r‖s in hex |
| `pubkey.{x,y}.hex` | Issuer JWK x/y as raw 32-byte hex |
| `issuer_jwk.json` | Full issuer JWK |
| `partial_sha.state.json` | `{state: [u32×8], cutoff, tail_len, total_len}` |
| `partial_sha.state.hex` | Partial SHA state, 8 u32s big-endian |
| `signing_input.tail.bin` | Raw unpadded tail bytes (circuit input after padding) |
| `signing_input.tail.padded.bin` | Tail zero-padded to 256 bytes |
| `Prover.toml` | Drop into `circuit/` to prove |

## Scope (prototype)

What this proves: *the prover possesses a Singpass-signed token over a specific message whose tail they commit to in-circuit*.

What's done:
- **SHA-256 is computed inside the circuit** (partial SHA — intermediate state precomputed off-circuit, tail hashed in-circuit). Prover-trust gap on the hash is closed.

What it doesn't (yet) — see `~/.claude/plans/i-m-building-a-prototype-idempotent-charm.md` for the roadmap:
- No claim parsing (no `iss` / `aud` / `exp` / `nonce` checks in-circuit) — **biggest remaining gap**.
- No nullifier — proofs replay.
- Single hardcoded issuer key.
- Uses MockPass keys, not production Singpass.
