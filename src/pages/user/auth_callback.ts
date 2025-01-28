import type { AstroCookies } from "astro";
import { actions } from "astro:actions";

export const prerender = false;

export async function GET({
  url,
  cookies,
  redirect,
  callAction,
}: {
  url: URL;
  cookies: AstroCookies;
  redirect: (url: string) => Response;
  callAction: (action: any, input: any) => any;
}) {
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");

  if (!state || !code) {
    return new Response("Missing state or code", { status: 400 });
  }

  // Verify the authorization code with IndieLogin.com
  const response = await fetch("https://indielogin.com/auth", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      code,
      redirect_uri: `${url.origin}${url.pathname}`,
      client_id: url.origin,
    }),
  });

  const respBody = await response.json();

  if (response.status === 200) {
    // User was logged in successfully
    const { me: userWebsite } = respBody;
    cookies.set("userWebsite", String(userWebsite), {
      path: "/",
      httpOnly: true,
      secure: import.meta.env.MODE !== "development",
      sameSite: "strict",
      maxAge: 60 * 60 * 24 * 365, // 1 year
    });

    const { data, error } = await callAction(actions.user.ensureUserExists, {
      userWebsite,
    });

    if (error) {
      return new Response(`Error creating user: ${error}`, { status: 500 });
    }

    return redirect("/");
  } else {
    return new Response(JSON.stringify(respBody), { status: 400 });
  }
}
