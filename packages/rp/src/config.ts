import {
  FAPI_BASE,
  DISCOVERY_URL,
  OUT_DIR,
} from "@singpass-zk/driver/src/paths.ts";

export const CLIENT_ID = process.env.CLIENT_ID ?? "mock-fapi-client-id";
export const REDIRECT_URI =
  process.env.REDIRECT_URI ?? "http://localhost:8000/callback";
export const SCOPES = "openid";
// MockPass profile to log in as (skip the HTML picker).
export const MOCK_NRIC = process.env.MOCK_NRIC ?? "S8979373D";
export const MOCK_UUID =
  process.env.MOCK_UUID ?? "a9865837-7bd7-46ac-bef4-42a76a946424";

export const Endpoints = {
  base: FAPI_BASE,
  discovery: DISCOVERY_URL,
  par: `${FAPI_BASE}/par`,
  auth: `${FAPI_BASE}/auth`,
  authCustomProfile: `${FAPI_BASE}/auth/custom-profile`,
  token: `${FAPI_BASE}/token`,
  jwks: `${FAPI_BASE}/.well-known/keys`,
};

export const OUT = OUT_DIR;
