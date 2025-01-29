import type { APIRoute } from "astro";
import { actions } from "astro:actions";
import { UAParser } from "ua-parser-js";

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

  // try to get the IP from cloudflare headers
  const cloudflareCountryCode =
    request.headers.get("CF-IPCountry") || undefined;

  // parse user agent
  const userAgent = request.headers.get("User-Agent");

  let os: string | undefined = undefined;
  let deviceType: string | undefined = undefined;
  let browser: string | undefined = undefined;

  if (userAgent) {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();
    os = result.os.name;
    deviceType = result.device.type;
    browser = result.browser.name;
  }

  const { data: saveSuccess, error: registerHitError } = await callAction(
    actions.hits.registerHit,
    {
      siteId: parseInt(siteId),
      path: pagePath!,
      referer: referrer || undefined,
      countryCode: cloudflareCountryCode,
      visitorOS: os,
      visitorDeviceType: deviceType,
      visitorBrowser: browser,
    }
  );

  if (registerHitError) {
    return new Response(`Register hit error: ${registerHitError}`, {
      status: 400,
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  if (!saveSuccess) {
    return new Response("Failed to save hit", {
      status: 500,
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  return new Response("Hit saved", {
    status: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
    },
  });
};
