import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { openSync } from "node:fs";
import { MOCKPASS_DIR, PID_FILE, LOG_FILE, MOCKPASS_PORT } from "./paths.ts";
import { waitUntilReady, isReady } from "./health.ts";

export async function startMockpass(): Promise<number> {
  if (await isReady()) {
    throw new Error(`MockPass already responding on port ${MOCKPASS_PORT}`);
  }
  if (!existsSync(`${MOCKPASS_DIR}/node_modules`)) {
    throw new Error(
      `MockPass deps not installed. Run: bun run mockpass:install`,
    );
  }

  const out = openSync(LOG_FILE, "a");
  const err = openSync(LOG_FILE, "a");

  const child = spawn("node", ["index.js"], {
    cwd: MOCKPASS_DIR,
    env: {
      ...process.env,
      MOCKPASS_PORT: String(MOCKPASS_PORT),
      MOCKPASS_STATELESS: "false",
      SHOW_LOGIN_PAGE: "false",
    },
    detached: true,
    stdio: ["ignore", out, err],
  });

  child.unref();
  if (child.pid == null) throw new Error("Failed to spawn MockPass");

  await writeFile(PID_FILE, String(child.pid), "utf8");
  await waitUntilReady();
  return child.pid;
}

export async function stopMockpass(): Promise<boolean> {
  if (!existsSync(PID_FILE)) return false;
  const pid = Number((await readFile(PID_FILE, "utf8")).trim());
  if (!Number.isFinite(pid)) {
    await unlink(PID_FILE);
    return false;
  }
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    // process already gone
  }
  await unlink(PID_FILE).catch(() => {});
  return true;
}
