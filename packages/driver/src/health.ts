import { DISCOVERY_URL } from "./paths.ts";

export async function waitUntilReady(timeoutMs = 30_000, intervalMs = 500): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(DISCOVERY_URL);
      if (res.ok) {
        await res.json();
        return;
      }
      lastErr = new Error(`discovery returned ${res.status}`);
    } catch (e) {
      lastErr = e;
    }
    await sleep(intervalMs);
  }
  throw new Error(`MockPass not ready after ${timeoutMs}ms: ${lastErr}`);
}

export async function isReady(): Promise<boolean> {
  try {
    const res = await fetch(DISCOVERY_URL, { signal: AbortSignal.timeout(1000) });
    return res.ok;
  } catch {
    return false;
  }
}

function sleep(ms: number) {
  return new Promise<void>((r) => setTimeout(r, ms));
}
