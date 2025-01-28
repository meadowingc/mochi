import type { AstroCookies } from "astro";

export async function GET({
  cookies,
  redirect,
}: {
  cookies: AstroCookies;
  redirect: (url: string) => Response;
}) {
  cookies.delete("userWebsite", {
    path: "/",
    httpOnly: true,
    secure: import.meta.env.MODE !== "development",
    sameSite: "strict",
  });
  return redirect("/");
}
