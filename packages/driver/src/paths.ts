import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = resolve(here, "../../..");
export const MOCKPASS_DIR = resolve(REPO_ROOT, "deps/mockpass");
export const CERTS_DIR = resolve(MOCKPASS_DIR, "static/certs");

export const RP_PRIVATE_JWKS = resolve(CERTS_DIR, "fapi-rp-private.json");
export const RP_PUBLIC_JWKS = resolve(CERTS_DIR, "fapi-rp-public.json");
export const ASP_PUBLIC_JWKS = resolve(CERTS_DIR, "fapi-asp-public.json");

export const OUT_DIR = resolve(REPO_ROOT, "out");
export const PID_FILE = resolve(REPO_ROOT, ".mockpass.pid");
export const LOG_FILE = resolve(REPO_ROOT, ".mockpass.log");

export const MOCKPASS_PORT = Number(process.env.MOCKPASS_PORT ?? 5156);
export const MOCKPASS_BASE = `http://localhost:${MOCKPASS_PORT}`;
export const FAPI_BASE = `${MOCKPASS_BASE}/singpass/v3/fapi`;
export const DISCOVERY_URL = `${FAPI_BASE}/.well-known/openid-configuration`;
