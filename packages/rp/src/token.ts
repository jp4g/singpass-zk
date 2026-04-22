import { Endpoints, CLIENT_ID, REDIRECT_URI } from "./config.ts";
import { CLIENT_ASSERTION_TYPE } from "./assertion.ts";

export type TokenResponse = {
  access_token: string;
  id_token: string;
  token_type: string;
};

export async function exchangeCode(args: {
  code: string;
  codeVerifier: string;
  clientAssertion: string;
  dpopProof: string;
}): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: args.code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: args.codeVerifier,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: args.clientAssertion,
  });

  const res = await fetch(Endpoints.token, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      dpop: args.dpopProof,
    },
    body,
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`token failed: ${res.status} ${text}`);
  return JSON.parse(text) as TokenResponse;
}
