import type { APIRoute } from "astro";
import { actions } from "astro:actions";

// This can be embedded as
// http://localhost:4321/reaper/embed/QWFQWFw.js
export const GET: APIRoute = async ({
  params,
  callAction,
  request,
  ...rest
}) => {
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

  // return 400 if the site requesting the script is not site?.url
  const siteUrl = new URL(site.url);

  const originRaw =
    request.headers.get("origin") || request.headers.get("referer");

  if (originRaw && siteUrl.origin !== new URL(originRaw).origin) {
    return new Response(
      `Origin '${originRaw}' does not match site origin '${siteUrl.origin}'`,
      { status: 401 }
    );
  }

  const currentDomain = import.meta.env.DEV
    ? "http://localhost:4321"
    : "https://mochi.meadow.cafe";

  // TODO: these need to be computed from DB for side
  const countryFlags = "🇦🇹🇧🇷🇨🇦🇨🇭🇨🇱🇨🇷🇩🇪🇫🇷🇬🇧🇮🇩🇮🇱🇮🇳🇳🇱🇳🇴🇳🇿🇵🇭🇷🇸🇹🇭🇺🇸";

  // You can add any logic here to customize the script based on the siteId
  const scriptContent = `
(function() {
  const pagePath = window.location.pathname;
  const encodedUrl = encodeURIComponent(window.location.href);
  const analyticsEndpoint = "${currentDomain}/reaper/${siteId}";
  const referrerUrl = document.referrer.indexOf(window.location.href) < 0 ? document.referrer : "";
  let shouldTrack = localStorage.getItem("mochi_ignore") == null;
  const ignoreParam = new URLSearchParams(document.location.search).get("mochi_ignore") || new URLSearchParams(document.location.search).get("mi");

  if (ignoreParam) {
    if (ignoreParam === "true" && localStorage.getItem("mochi_ignore") == null) {
      localStorage.setItem("mochi_ignore", "true");
      shouldTrack = false;
      alert("mochi will no longer track your own hits in this browser.");
    } else if (ignoreParam === "false" && localStorage.getItem("mochi_ignore") != null) {
      localStorage.removeItem("mochi_ignore");
      shouldTrack = true;
      alert("mochi has been enabled for this website, for this browser.");
    }
  }

  if (shouldTrack) {
    fetch(\`\${analyticsEndpoint}?url=\${encodedUrl}&path=\${pagePath}&referrer=\${referrerUrl}\`, { method: "POST" });
  }

  const countriesElement = document.querySelector(".mochi_countries");
  if (countriesElement) {
    countriesElement.innerHTML = "${countryFlags}";
  }
})();
  `.trim();

  return new Response(scriptContent, {
    headers: {
      "Content-Type": "application/javascript; charset=utf-8",
    },
  });
};
