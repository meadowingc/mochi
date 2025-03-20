(function () {
  const pagePath = window.location.pathname;
  const encodedUrl = encodeURIComponent(window.location.href);
  const analyticsEndpoint = "{{publicURL}}/reaper/{{ownerUsername}}/{{site.ID}}";
  const referrerUrl = document.referrer.indexOf(window.location.href) < 0 ? document.referrer : "";
  let shouldTrack = localStorage.getItem("mochi_ignore") == null;
  const ignoreParam = new URLSearchParams(document.location.search).get("mochi_ignore") || new URLSearchParams(document.location.search).get("mi");

  let hasTracked = false;

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

  function sendTrackingRequest() {
    if (shouldTrack && !hasTracked) {
      hasTracked = true;
      fetch(`${analyticsEndpoint}?url=${encodedUrl}&path=${pagePath}&referrer=${referrerUrl}`, { method: "POST" });
    }
  }

  function setupHumanInteractionDetection() {
    document.addEventListener('mousemove', handlePotentialHumanInteraction, { once: true });
    document.addEventListener('keydown', handlePotentialHumanInteraction, { once: true });
    document.addEventListener('touchstart', handlePotentialHumanInteraction, { once: true });

    // Fallback: Track after 30 seconds even without interaction
    setTimeout(sendTrackingRequest, 30000);
  }

  function handlePotentialHumanInteraction(event) {
    // For mousemove, check if there's actual movement (not just a simulated event)
    if (event.type === 'mousemove') {
      if (event.movementX !== 0 || event.movementY !== 0) {
        sendTrackingRequest();
      }
    } else {
      // For other events (keydown, touchstart) just send the request
      sendTrackingRequest();
    }
  }
  
  setupHumanInteractionDetection();

  const countriesElement = document.querySelector(".mochi_countries");
  if (countriesElement) {
    countriesElement.innerHTML = "{{countryFlags}}";
  }
})()
