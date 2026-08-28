import { createRequestHandler, type ServerBuild } from "@remix-run/cloudflare";
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore This file won't exist if it hasn't yet been built
import * as build from "./build/server";
import { getLoadContext } from "./load-context";

// --- OpenAuth Configuration ---
const AUTH_URL = "https://login.tunlz.dev";
const CLIENT_ID = "your-client-id";
const APP_URL = "https://todo.tunlz.dev";
const COOKIE_NAME = "auth_token";

function redirectToLogin(): Response {
  const loginUrl = new URL(AUTH_URL + "/authorize");
  loginUrl.searchParams.set("redirect_uri", APP_URL + "/callback");
  loginUrl.searchParams.set("client_id", CLIENT_ID);
  loginUrl.searchParams.set("response_type", "code");
  return Response.redirect(loginUrl.toString(), 302);
}

function getCookie(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  for (const cookie of cookies) {
    const [key, ...valueParts] = cookie.split("=");
    if (key.trim() === name) {
      return valueParts.join("=");
    }
  }
  return null;
}

async function verifyToken(token: string): Promise<{ id: string } | null> {
  try {
    const resp = await fetch(AUTH_URL + "/verify", {
      headers: { Authorization: "Bearer " + token },
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const handleRemixRequest = createRequestHandler(build as any as ServerBuild);

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // --- OAuth Callback Route ---
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      if (!code) {
        return new Response("Missing authorization code", { status: 400 });
      }

      const tokenResp = await fetch(AUTH_URL + "/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: CLIENT_ID,
          redirect_uri: APP_URL + "/callback",
        }),
      });

      if (!tokenResp.ok) {
        return new Response("Failed to exchange code for token", { status: 400 });
      }

      const tokens = (await tokenResp.json()) as { access_token?: string };
      if (!tokens.access_token) {
        return new Response("No access token in response", { status: 400 });
      }

      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie":
            COOKIE_NAME +
            "=" +
            tokens.access_token +
            "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" +
            60 * 60 * 24 * 7,
        },
      });
    }

    // --- Logout Route ---
    if (url.pathname === "/logout" && request.method === "POST") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie":
            COOKIE_NAME + "=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
        },
      });
    }

    // --- Auth Middleware ---
    const token = getCookie(request, COOKIE_NAME);

    if (!token) {
      return redirectToLogin();
    }

    const user = await verifyToken(token);
    if (!user) {
      return redirectToLogin();
    }

    // --- Authenticated: hand off to Remix ---
    try {
      const loadContext = getLoadContext({
        request,
        context: {
          cloudflare: {
            cf: request.cf,
            ctx: {
              waitUntil: ctx.waitUntil.bind(ctx),
              passThroughOnException: ctx.passThroughOnException.bind(ctx),
              props: {},
            },
            caches,
            env,
          },
        },
      });
      return await handleRemixRequest(request, loadContext);
    } catch (error) {
      console.log(error);
      return new Response("An unexpected error occurred", { status: 500 });
    }
  },
} satisfies ExportedHandler<Env>;
