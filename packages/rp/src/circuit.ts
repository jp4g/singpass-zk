import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { CompiledCircuit } from "@noir-lang/noir_js";
import { REPO_ROOT } from "@singpass-zk/driver/src/paths.ts";

const DEFAULT_PATH = resolve(REPO_ROOT, "circuit/target/singpass_zk.json");

export async function loadCompiledCircuit(
  path: string = DEFAULT_PATH,
): Promise<CompiledCircuit> {
  const raw = await readFile(path, "utf8");
  return JSON.parse(raw) as CompiledCircuit;
}
