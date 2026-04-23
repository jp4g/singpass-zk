# singpass-zk

Prove possession of a valid Singpass-issued OIDC ID token, in zero knowledge, inside a Noir circuit. The verifier sees four `Field`s — three Poseidon2 commitments + the token expiry — and learns nothing else about the holder.

> Prototype. Targets [MockPass](https://github.com/opengovsg/mockpass) (the open-source Singpass mock); see [Roadmap](#roadmap) for the production swap.

---

## What it proves

The circuit (`circuit/src/main.nr`) consumes a Singpass FAPI ID token (a JWE-wrapped JWS) and asserts:

1. **Signature**: ECDSA P-256 verification over the SHA-256 of the JWS signing input — both the SHA and the ECDSA happen in-circuit, so the prover can't substitute a digest they happen to hold.
2. **Structure**: the JWS payload (extracted by base64url-decoding the bytes after the `.`) parses as JSON.
3. **Claims**: five claims — `iss`, `aud`, `exp`, `nonce`, `sub` — are read out of that JSON.

It then emits four public outputs:

| Output | Meaning | Verifier action |
| --- | --- | --- |
| `key_hash` | `poseidon2(pack(pubX ‖ pubY))` over the issuer's signing key | Pin to known Singpass JWKS pubkey hash; reject mismatch |
| `iss_aud_hash` | `poseidon2(pack(iss), iss.len, pack(aud), aud.len)` | Pin to (issuer URL, your client_id) hash; reject mismatch |
| `nullifier` | `poseidon2(pack(sub), sub.len, pack(nonce), nonce.len)` | Insert into your dedup table; reject duplicates |
| `exp` | UNIX expiry timestamp from the token | Check `exp > now`; reject expired |

The pubkey and the raw claim values are private inputs — they never leave the circuit.

## Layout

```
circuit/                Noir circuit + per-step constants/utils modules
packages/driver/        MockPass lifecycle + JWKS loader (Node-only)
packages/rp/            FAPI flow + SDK: SingpassProver, oracle hashes,
                        DTO serialization, browser-safe entrypoint
packages/bench-browser/ Vite dev app: live OIDC + in-browser UltraHonk
                        prove + verify, with timings and verifier checklist
deps/mockpass/          Git submodule (opengovsg/mockpass)
patches/                Local patches against the submodule
```

## Quick start (Docker)

```bash
git clone --recurse-submodules <this repo>
cd singpass-zk
bun run docker:up
```

Open <http://localhost:5173>. Bench loads, click **Prove UltraHonk**, watch the verifier checklist go green. `bun run docker:down` to stop.

The compose stack runs MockPass and the bench dev server on a private network. The browser fetches the static bundle from the bench container and runs the WASM proving locally on your CPU.

## Quick start (native)

Requires [Bun](https://bun.com) ≥ 1.3 and [`noirup`](https://github.com/noir-lang/noirup) (for `nargo`).

```bash
git submodule update --init --recursive
bun install
bun run mockpass:install     # patch + npm install inside the submodule
noirup -v 1.0.0-beta.20      # nargo + acvm + UltraHonk-compatible toolchain
bun run circuit:compile      # produces circuit/target/singpass_zk.json
bun install                  # re-run so bench-browser postinstall copies the artifact

bun run driver:up            # MockPass on :5156, detached
bun test                     # full e2e: OIDC -> witness -> prove -> verify -> oracle
bun run bench:dev            # OR open the browser bench at http://localhost:5173
bun run driver:down          # stop MockPass
```

## How it fits together

```
Browser                       Vite middleware                    MockPass
                            (server-side, runs once
                              per page load / per
                              `bun test` invocation)

   ┌─ /api/oidc ─────►  runOidcFlow()  ──── PAR ────►  /par
                          │
                          ├──── auth code dance ────►  /auth/custom-profile
                          │
                          ├──── token exchange ─────►  /token
                          │     (returns JWE)
                          │
                          ▼
                     decryptAndVerify()  (jose)
                          │
                          ▼
                   VerifiedIdToken
                          │
   ◄─── DTO JSON ─────────┘
        (Uint8Arrays as hex)

   deserialize → buildCircuitInputs → Noir.execute → witness
                                                       │
                                                       ▼
                                       UltraHonkBackend.generateProof
                                                       │
                                                       ▼
                                       UltraHonkBackend.verifyProof
                                                       │
                                                       ▼
                                       4 public outputs ━━━━━ display + oracle check
```

The OIDC dance needs the RP's private FAPI keys (`deps/mockpass/static/certs/fapi-rp-private.json`), so it stays server-side. The browser only deals with the in-circuit work.

## Repository scripts

| Script | Effect |
| --- | --- |
| `bun run docker:up` | Init submodule + `docker compose up --build` |
| `bun run docker:down` | `docker compose down -v` |
| `bun run driver:up` / `:down` / `:status` | Manage the MockPass subprocess (native dev) |
| `bun test` | E2E: live OIDC + UltraHonk prove + verify + oracle equality |
| `bun run bench:dev` | Vite dev server for the browser bench (`http://localhost:5173`) |
| `bun run circuit:compile` | `nargo compile` → `circuit/target/singpass_zk.json` |
| `bun run mockpass:install` | Apply patches + npm install in the submodule |

## SDK (`@singpass-zk/rp`)

Two entry points:

```ts
// Node entry — full surface
import {
  runOidcFlow, isMockpassReady,            // OIDC client (server-only)
  SingpassProver, loadCompiledCircuit,     // proving
  expectedKeyHash, expectedIssAudHash,     // off-circuit oracle
  serialize, deserialize,                  // DTO for Node→browser hop
} from "@singpass-zk/rp";

// Browser entry — node:fs / node:crypto-free
import {
  SingpassProver,                          // long-lived Noir + Barretenberg
  expectedKeyHash, expectedIssAudHash,     // oracle
  deserialize,                             // hex → Uint8Array
} from "@singpass-zk/rp/browser";
```

`SingpassProver` holds a single Barretenberg backend across many proofs (avoids re-init cost and a socket race when destroying + recreating the backend). The class exposes `prove()` (full path) plus split methods `executeWitness()` / `generateProofFromWitness()` / `verifyProof()` so a benchmark can time each phase.

## Roadmap

What's done:
- SHA-256 + ECDSA P-256 + base64url decode + JSON parse + claim extraction, all in-circuit
- Poseidon2 commitments for pubkey, (iss, aud), and (sub, nonce)
- `exp` exposed for off-circuit freshness check
- E2E test suite + browser bench + Docker compose

What's not (in rough priority order):
- **Nullifier dedup** — circuit emits the nullifier; we don't store/check duplicates anywhere
- **JWKS rotation** — pubkey is matched against a single pinned commitment. Production needs a Merkle root over a rotating JWKS
- **Production Singpass swap** — endpoints, RP enrollment, real client_id, real key material; today we hit MockPass on `localhost:5156`
- **DPoP binding** — production tokens may carry `cnf.jkt`; not parsed yet
- **Variable signing-input length without recompile** — `MAX_SIGNING_INPUT = 768` is a comptime ceiling

## Patches

`patches/mockpass-iat-floor.patch` floors MockPass's `iat` claim. MockPass emits `Date.now() / 1000` (a float); the in-circuit JSON parser is integer-only for numbers and barfs on the `.`. Real Singpass emits integer `iat` per FAPI, so this is a MockPass-only quirk. Applied idempotently by `bun run mockpass:install` (and via a `patch -p1` step inside `Dockerfile.mockpass`).

## License

[MIT](LICENSE).
