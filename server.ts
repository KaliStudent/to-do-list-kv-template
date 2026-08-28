import { createRequestHandler, type ServerBuild } from "@remix-run/cloudflare";
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore This file won't exist if it hasn't yet been built
import * as build from "./build/server";
import { getLoadContext } from "./load-context";
import { createClient } from "@openauthjs/openauth/client";

// --- OpenAuth Configuration ---
const AUTH_URL = "https://login.tunlz.dev";
const CLIENT_ID = "your-client-id";
const APP_URL = "https://todo.tunlz.dev";
const COOKIE_NAME = "auth_token";

const auth = createClient({
	issuer: AUTH_URL,
	client_id: CLIENT_ID,
});

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
	for (const cookie of cookieHeader.split(";").map((c) => c.trim())) {
		const [key, ...valueParts] = cookie.split("=");
		if (key.trim() === name) return valueParts.join("=");
	}
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const handleRemixRequest = createRequestHandler(build as any as ServerBuild);

export default {
	async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

		// --- OAuth Callback ---
		if (url.pathname === "/callback") {
			const code = url.searchParams.get("code");
			if (!code) return new Response("Missing code", { status: 400 });

			try {
				const tokens = await auth.callback({
					redirect_uri: APP_URL + "/callback",
					code,
				});
				if (!tokens.access) return new Response("No token received", { status: 400 });

				return new Response(null, {
					status: 302,
					headers: {
						Location: "/",
						"Set-Cookie": `${COOKIE_NAME}=${tokens.access}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
					},
				});
			} catch (error) {
				console.log("Token exchange failed:", error);
				return new Response("Token exchange failed", { status: 400 });
			}
		}

		// --- Logout ---
		if (url.pathname === "/logout" && request.method === "POST") {
			return new Response(null, {
				status: 302,
				headers: {
					Location: "/",
					"Set-Cookie": `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
				},
			});
		}

		// --- Auth Middleware ---
		const token = getCookie(request, COOKIE_NAME);
		if (!token) return redirectToLogin();

		try {
			const verified = await auth.verify(token);
			if (!verified) return redirectToLogin();
		} catch {
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
