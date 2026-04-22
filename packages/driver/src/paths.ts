import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = resolve(here, "../../..");
export const MOCKPASS_DIR = resolve(REPO_ROOT, "deps/mockpass");

export const RP_PRIVATE_JWKS = resolve(
  MOCKPASS_DIR,
  "static/certs/fapi-rp-private.json",
);

export const PID_FILE = resolve(REPO_ROOT, ".mockpass.pid");
export const LOG_FILE = resolve(REPO_ROOT, ".mockpass.log");

export const MOCKPASS_HOST = process.env.MOCKPASS_HOST ?? "localhost";
export const MOCKPASS_PORT = Number(process.env.MOCKPASS_PORT ?? 5156);
export const MOCKPASS_BASE = `http://${MOCKPASS_HOST}:${MOCKPASS_PORT}`;
export const FAPI_BASE = `${MOCKPASS_BASE}/singpass/v3/fapi`;
export const DISCOVERY_URL = `${FAPI_BASE}/.well-known/openid-configuration`;
