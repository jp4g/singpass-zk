import {
  expectedKeyHash,
  expectedIssAudHash,
  deserialize,
  type VerifiedIdTokenDto,
  type VerifiedIdToken,
} from "@singpass-zk/rp/browser";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { runBenchmark } from "./bench";

type Payload = {
  iss: string;
  aud: string;
  nonce: string;
  sub: string;
  exp: number;
  iat?: number;
  nbf?: number;
};

type Header = {
  alg?: string;
  kid?: string;
};

const $ = (id: string): HTMLElement => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
};

const log = (line: string): void => {
  $("logs").textContent += line + "\n";
};

async function boot(): Promise<void> {
  try {
    log("loading circuit…");
    const circuitRes = await fetch("/singpass_zk.json");
    if (!circuitRes.ok) {
      throw new Error(
        `GET /singpass_zk.json -> ${circuitRes.status}. ` +
          `Did you run \`bun run circuit:compile\` and \`bun install\`?`,
      );
    }
    const circuit = (await circuitRes.json()) as CompiledCircuit;
    log(`  circuit loaded`);

    log("requesting fresh OIDC token from /api/oidc…");
    const oidcRes = await fetch("/api/oidc");
    if (!oidcRes.ok) {
      const body = (await oidcRes.json().catch(() => ({}))) as { error?: string };
      throw new Error(
        `GET /api/oidc -> ${oidcRes.status}: ${body.error ?? "(no body)"}`,
      );
    }
    const dto = (await oidcRes.json()) as VerifiedIdTokenDto;
    const verified = deserialize(dto);
    const payload = verified.payload as Payload;
    const header = verified.header as Header;

    renderTokenInfo(verified, payload, header);
    renderExpectedCommitments(verified, payload);
    log(`  token sub=${payload.sub} exp=${payload.exp}`);

    const runBtn = $("run") as HTMLButtonElement;
    runBtn.disabled = false;
    runBtn.addEventListener("click", () => {
      void run(circuit, verified, payload);
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log(`ERROR: ${msg}`);
    const list = $("token-info-list");
    list.innerHTML = "";
    const dt = document.createElement("dt");
    dt.textContent = "error";
    const dd = document.createElement("dd");
    dd.textContent = msg;
    list.appendChild(dt);
    list.appendChild(dd);
  }
}

async function run(
  circuit: CompiledCircuit,
  verified: VerifiedIdToken,
  payload: Payload,
): Promise<void> {
  const runBtn = $("run") as HTMLButtonElement;
  runBtn.disabled = true;

  const stamp = new Date().toISOString().slice(11, 19);
  log(`\n=== run @ ${stamp} ===`);

  try {
    const iters = Number((($("iters") as HTMLInputElement).value as string));
    const useThreads = ($("threads") as HTMLInputElement).checked;
    const threads = useThreads ? navigator.hardwareConcurrency || 8 : 1;

    const result = await runBenchmark({
      circuit,
      verified,
      iterations: iters,
      threads,
      log,
    });

    const r0 = result.lastProof;
    const expectedKH = expectedKeyHash(verified.pubX, verified.pubY);
    const expectedIA = expectedIssAudHash(payload.iss, payload.aud);
    // No expectedNullifier — a real verifier doesn't have sub/nonce, they
    // just receive the nullifier from the proof and dedupe.

    const now = Math.floor(Date.now() / 1000);
    const expDelta = r0.publicOutputs.exp - now;

    const checks: Check[] = [
      {
        ok: r0.verified ? "ok" : "fail",
        label: r0.verified
          ? "Proof verified by UltraHonk backend"
          : "Proof FAILED to verify",
        detail: `${r0.proof.byteLength} bytes, ${r0.publicInputs.length} public inputs`,
      },
      {
        ok: r0.publicOutputs.keyHash === expectedKH ? "ok" : "fail",
        label: "key_hash matches Singpass JWKS pubkey commitment",
        detail:
          r0.publicOutputs.keyHash === expectedKH
            ? `0x${r0.publicOutputs.keyHash.toString(16)}`
            : `proof   = 0x${r0.publicOutputs.keyHash.toString(16)}\nexpected = 0x${expectedKH.toString(16)}`,
      },
      {
        ok: r0.publicOutputs.issAudHash === expectedIA ? "ok" : "fail",
        label: "iss_aud_hash matches pinned (issuer, client_id) commitment",
        detail:
          r0.publicOutputs.issAudHash === expectedIA
            ? `0x${r0.publicOutputs.issAudHash.toString(16)}`
            : `proof   = 0x${r0.publicOutputs.issAudHash.toString(16)}\nexpected = 0x${expectedIA.toString(16)}`,
      },
      {
        ok: expDelta > 0 ? "ok" : "fail",
        label:
          expDelta > 0
            ? "Token freshness: exp > now"
            : "Token EXPIRED: exp <= now",
        detail:
          `exp = ${r0.publicOutputs.exp} (${new Date(r0.publicOutputs.exp * 1000).toISOString().slice(0, 19)}Z)\n` +
          `now = ${now} (${new Date(now * 1000).toISOString().slice(0, 19)}Z)\n` +
          (expDelta > 0
            ? `${expDelta}s remaining`
            : `expired ${-expDelta}s ago — refresh page for a fresh token`),
      },
      {
        ok: "warn",
        label: "Nullifier reuse: ignored",
        detail:
          `prototype: this bench doesn't keep a nullifier dedup DB. ` +
          `Production verifiers reject duplicates.\n` +
          `nullifier = 0x${r0.publicOutputs.nullifier.toString(16)}`,
      },
    ];

    renderVerifierRun(stamp, checks);
  } catch (e) {
    log(`ERROR: ${e instanceof Error ? e.message : String(e)}`);
    renderVerifierRun(stamp, [
      {
        ok: "fail",
        label: "Run threw an error",
        detail: e instanceof Error ? e.message : String(e),
      },
    ]);
  } finally {
    runBtn.disabled = false;
  }
}

function renderTokenInfo(
  v: VerifiedIdToken,
  payload: Payload,
  header: Header,
): void {
  const list = $("token-info-list");
  const fmtTs = (s: number) =>
    `${s} (${new Date(s * 1000).toISOString().replace("T", " ").slice(0, 19)}Z)`;
  const fmtRelExp = (s: number) => {
    const delta = s - Math.floor(Date.now() / 1000);
    if (delta <= 0) return ` ⚠ EXPIRED ${-delta}s ago`;
    const min = Math.floor(delta / 60);
    const sec = delta % 60;
    return ` (in ${min}m ${sec}s)`;
  };

  list.innerHTML = "";
  const rows: [string, string][] = [
    ["sub", payload.sub],
    ["iss", payload.iss],
    ["aud", payload.aud],
    ["exp", `${fmtTs(payload.exp)}${fmtRelExp(payload.exp)}`],
    ["nonce", truncMid(payload.nonce, 24, 12)],
    ["alg", header.alg ?? "(absent)"],
    ["kid", header.kid ?? "(absent)"],
    ["pubX", truncMid(toHex(v.pubX))],
    ["pubY", truncMid(toHex(v.pubY))],
    [
      "signing_input",
      `${v.signingInput.length} bytes (header=${v.jws.header.length} b64 chars + "." + payload)`,
    ],
  ];
  for (const [k, val] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = val;
    list.appendChild(dt);
    list.appendChild(dd);
  }
}

function renderExpectedCommitments(
  v: VerifiedIdToken,
  payload: Payload,
): void {
  const list = $("commitments-list");
  list.innerHTML = "";

  const keyHash = expectedKeyHash(v.pubX, v.pubY);
  const issAudHash = expectedIssAudHash(payload.iss, payload.aud);

  const issBytes = new TextEncoder().encode(payload.iss).length;
  const audBytes = new TextEncoder().encode(payload.aud).length;

  appendCommitment(list, {
    name: "key_hash",
    form: "poseidon2( pack(pubX || pubY) )",
    inputs: [
      ["pubX", toHex(v.pubX)],
      ["pubY", toHex(v.pubY)],
    ],
    hash: keyHash,
  });
  appendCommitment(list, {
    name: "iss_aud_hash",
    form: "poseidon2( pack(iss), iss.len, pack(aud), aud.len )",
    inputs: [
      ["iss", `"${payload.iss}"  (${issBytes} bytes)`],
      ["aud", `"${payload.aud}"  (${audBytes} bytes)`],
    ],
    hash: issAudHash,
  });
}

function appendCommitment(
  list: HTMLElement,
  c: {
    name: string;
    form: string;
    inputs: Array<[string, string]>;
    hash: bigint;
  },
): void {
  const block = document.createElement("div");
  block.className = "commitment";

  const name = document.createElement("div");
  name.className = "commitment-name";
  name.textContent = c.name;
  block.appendChild(name);

  const form = document.createElement("div");
  form.className = "commitment-form";
  form.textContent = c.form;
  block.appendChild(form);

  const inputsBox = document.createElement("div");
  inputsBox.className = "commitment-inputs";
  for (const [k, v] of c.inputs) {
    const line = document.createElement("div");
    const key = document.createElement("span");
    key.textContent = `${k} = `;
    const val = document.createElement("span");
    val.className = "v";
    val.textContent = v;
    line.appendChild(key);
    line.appendChild(val);
    inputsBox.appendChild(line);
  }
  block.appendChild(inputsBox);

  const hash = document.createElement("div");
  hash.className = "commitment-hash";
  hash.textContent = "0x" + c.hash.toString(16);
  block.appendChild(hash);

  list.appendChild(block);
}

type Check = {
  ok: "ok" | "warn" | "fail";
  label: string;
  detail: string;
};

function renderVerifierRun(stamp: string, checks: readonly Check[]): void {
  const verifier = $("verifier");
  // Replace the empty-state placeholder on first run.
  const empty = verifier.querySelector(".verifier-empty");
  if (empty) verifier.innerHTML = "";

  const block = document.createElement("div");
  block.className = "verifier-run";

  const heading = document.createElement("div");
  heading.className = "verifier-stamp";
  heading.textContent = `run @ ${stamp}`;
  block.appendChild(heading);

  for (const c of checks) {
    const row = document.createElement("div");
    row.className = "check";
    const icon = document.createElement("span");
    icon.className = `check-icon ${c.ok}`;
    icon.textContent = c.ok === "ok" ? "✓" : c.ok === "warn" ? "◯" : "✗";
    row.appendChild(icon);
    const body = document.createElement("div");
    body.className = "check-body";
    const label = document.createElement("div");
    label.className = "check-label";
    label.textContent = c.label;
    const detail = document.createElement("div");
    detail.className = "check-detail";
    detail.textContent = c.detail;
    body.appendChild(label);
    body.appendChild(detail);
    row.appendChild(body);
    block.appendChild(row);
  }

  // Newest run on top.
  verifier.insertBefore(block, verifier.firstChild);
}

// Local toHex (rather than importing from @singpass-zk/rp's b64.ts) because
// b64.ts uses Buffer; even with vite-plugin-node-polyfills it's wasteful
// to drag the polyfill in just for hex.
function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function truncMid(s: string, head = 16, tail = 8): string {
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}

void boot();
