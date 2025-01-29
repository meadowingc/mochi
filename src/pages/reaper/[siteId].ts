import type { APIRoute } from "astro";
import { actions } from "astro:actions";

// This can be embedded as
// http://localhost:4321/reaper/embed/QWFQWFw.js
export const POST: APIRoute = async ({ params, callAction, url, request }) => {
  // TODO: this should only be accessible from the origin of the site registered by the user

  const { siteId } = params;

  if (!siteId) {
    return new Response("Missing siteId", { status: 400 });
  }

  const { data: site, error: getSiteError } = await callAction(
    actions.site.getSiteById,
    {
      siteId: parseInt(siteId),
    }
  );

  if (getSiteError) {
    return new Response(`Get site error: ${getSiteError}`, { status: 400 });
  }

  if (!site) {
    return new Response("Site not found", { status: 404 });
  }

  const currentDomain = url.searchParams.get("url");
  const pagePath = url.searchParams.get("path");
  const referrer = url.searchParams.get("referrer");

  const { data: saveSuccess, error: registerHitError } = await callAction(
    actions.hits.registerHit,
    {
      siteId: parseInt(siteId),
      path: pagePath!,
      referer: referrer || undefined,
      visitorIpHash: "123",
      visitorUserAgentHash: "123",
      countryCode: "US",
    }
  );

  if (registerHitError) {
    return new Response(`Register hit error: ${registerHitError}`, {
      status: 400,
    });
  }

  if (!saveSuccess) {
    return new Response("Failed to save hit", { status: 500 });
  }

  return new Response("Hit saved", { status: 200 });
};
