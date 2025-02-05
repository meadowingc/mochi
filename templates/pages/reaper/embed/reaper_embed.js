(function() {
  const pagePath = window.location.pathname;
  const encodedUrl = encodeURIComponent(window.location.href);
  const analyticsEndpoint = "{{publicURL}}/reaper/{{signedInUser.Username}}/{{site.ID}}";
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
    fetch(`${analyticsEndpoint}?url=${encodedUrl}&path=${pagePath}&referrer=${referrerUrl}`, { method: "POST" });
  }

  const countriesElement = document.querySelector(".mochi_countries");
  if (countriesElement) {
    countriesElement.innerHTML = "{{countryFlags}}";
  }
})()
