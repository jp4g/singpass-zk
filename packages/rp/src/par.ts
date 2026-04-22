import { Endpoints, CLIENT_ID, REDIRECT_URI, SCOPES } from "./config.ts";
import { CLIENT_ASSERTION_TYPE } from "./assertion.ts";

export type ParResponse = {
  request_uri: string;
  expires_in: number;
};

export async function pushAuthorizationRequest(args: {
  clientAssertion: string;
  dpopProof: string;
  codeChallenge: string;
  state: string;
  nonce: string;
}): Promise<ParResponse> {
  const body = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state: args.state,
    nonce: args.nonce,
    code_challenge: args.codeChallenge,
    code_challenge_method: "S256",
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: args.clientAssertion,
  });

  const res = await fetch(Endpoints.par, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      dpop: args.dpopProof,
    },
    body,
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`PAR failed: ${res.status} ${text}`);
  }
  return JSON.parse(text) as ParResponse;
}
