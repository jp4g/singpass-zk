import { Endpoints, CLIENT_ID, MOCK_NRIC, MOCK_UUID } from "./config.ts";

// MockPass's /auth/custom-profile bypasses the HTML picker and redirects
// straight to ?code=...&state=... — we intercept the 302 manually since
// the redirect_uri isn't a real listening server in this prototype.
export async function walkAuth(request_uri: string): Promise<{
  code: string;
  state: string;
}> {
  const url = new URL(Endpoints.authCustomProfile);
  url.searchParams.set("nric", MOCK_NRIC);
  url.searchParams.set("uuid", MOCK_UUID);
  url.searchParams.set("request_uri", request_uri);
  url.searchParams.set("client_id", CLIENT_ID);

  const res = await fetch(url, { redirect: "manual" });
  if (res.status !== 302) {
    const body = await res.text();
    throw new Error(
      `custom-profile expected 302, got ${res.status}: ${body}`,
    );
  }
  const location = res.headers.get("location");
  if (!location) throw new Error("custom-profile missing Location header");

  const loc = new URL(location);
  const code = loc.searchParams.get("code");
  const state = loc.searchParams.get("state");
  if (!code || !state) {
    throw new Error(`redirect missing code/state: ${location}`);
  }
  return { code, state };
}
