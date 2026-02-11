(function () {
  const pagePath = encodeURIComponent(window.location.pathname);
  const encodedUrl = encodeURIComponent(window.location.href);
  const analyticsEndpoint = "{{publicURL}}/reaper/{{ownerUsername}}/{{site.ID}}";
  const referrerUrl = document.referrer.indexOf(window.location.href) < 0 ? encodeURIComponent(document.referrer) : "";
  let shouldTrack = localStorage.getItem("mochi_ignore") == null;
  const ignoreParam = new URLSearchParams(document.location.search).get("mochi_ignore") || new URLSearchParams(document.location.search).get("mi");

  let hasTracked = false;
  let fallbackTimeout = null;

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

  function cleanupListeners() {
    document.removeEventListener('mousemove', handlePotentialHumanInteraction);
    document.removeEventListener('keydown', handlePotentialHumanInteraction);
    document.removeEventListener('touchstart', handlePotentialHumanInteraction);
    document.removeEventListener('scroll', handlePotentialHumanInteraction);
    document.removeEventListener('click', handlePotentialHumanInteraction);

    if (fallbackTimeout) {
      clearTimeout(fallbackTimeout);
      fallbackTimeout = null;
    }
  }

  function sendTrackingRequest() {
    if (shouldTrack && !hasTracked) {
      hasTracked = true;
      cleanupListeners();
      fetch(`${analyticsEndpoint}?url=${encodedUrl}&path=${pagePath}&referrer=${referrerUrl}`, { method: "POST" });
    }
  }

  function setupHumanInteractionDetection() {
    if (!shouldTrack) return;

    document.addEventListener('mousemove', handlePotentialHumanInteraction, { once: true });
    document.addEventListener('keydown', handlePotentialHumanInteraction, { once: true });
    document.addEventListener('touchstart', handlePotentialHumanInteraction, { once: true });
    document.addEventListener('scroll', handlePotentialHumanInteraction, { once: true });
    document.addEventListener('click', handlePotentialHumanInteraction, { once: true });

    // Fallback: Track after 30 seconds even without interaction
    fallbackTimeout = setTimeout(sendTrackingRequest, 30000);
  }

  function handlePotentialHumanInteraction(event) {
    // For mousemove, check if there's actual movement (not just a simulated event)
    if (event.type === 'mousemove') {
      // Check for movement, but also accept if isTrusted is true (real user event)
      if (event.isTrusted && (event.movementX !== 0 || event.movementY !== 0 || event.screenX > 0 || event.screenY > 0)) {
        sendTrackingRequest();
      }
    } else {
      // For other events (keydown, touchstart, scroll, click) just send the request if trusted
      if (event.isTrusted) {
        sendTrackingRequest();
      }
    }
  }

  setupHumanInteractionDetection();

  const countriesElement = document.querySelector(".mochi_countries");
  if (countriesElement) {
    countriesElement.innerHTML = "{{countryFlags}}";
  }

  {% if kudosEnabled %}
  // Kudos functionality
  (function() {
    const kudosEndpoint = "{{publicURL}}/reaper/{{ownerUsername}}/{{site.ID}}/kudo";
    const kudosEmoji = "{{kudosEmoji}}";
    const siteID = "{{site.ID}}";

    function getKudosStorageKey(path) {
      return "mochi_kudos_" + siteID + "_" + path;
    }

    function initKudosButtons() {
      const buttons = document.querySelectorAll(".mochi_kudos");
      if (buttons.length === 0) return;

      buttons.forEach(function(button) {
        const path = button.getAttribute("data-path") || window.location.pathname;
        const isPrivate = button.getAttribute("data-private") === "true";
        const alreadyKudoed = localStorage.getItem(getKudosStorageKey(path)) != null;

        // Set initial state
        if (alreadyKudoed) {
          button.classList.add("did_kudo");
          button.disabled = true;
        }

        // Fetch current count
        fetch(kudosEndpoint + "?path=" + encodeURIComponent(path))
          .then(function(res) { return res.json(); })
          .then(function(data) {
            var count = data.count || 0;
            if (kudosEmoji === "custom") {
              button.textContent = isPrivate ? "" : String(count);
            } else {
              button.textContent = isPrivate ? kudosEmoji : kudosEmoji + " " + count;
            }
          })
          .catch(function() {
            if (kudosEmoji !== "custom") {
              button.textContent = kudosEmoji;
            }
          });

        // Handle click
        if (!alreadyKudoed) {
          button.addEventListener("click", function() {
            if (button.disabled) return;

            button.disabled = true;
            button.classList.add("did_kudo");

            fetch(kudosEndpoint + "?path=" + encodeURIComponent(path), { method: "POST" })
              .then(function(res) { return res.json(); })
              .then(function(data) {
                localStorage.setItem(getKudosStorageKey(path), "true");
                var count = data.count || 0;
                if (kudosEmoji === "custom") {
                  button.textContent = isPrivate ? "" : String(count);
                } else {
                  button.textContent = isPrivate ? kudosEmoji : kudosEmoji + " " + count;
                }
              })
              .catch(function() {
                // Re-enable on error
                button.disabled = false;
                button.classList.remove("did_kudo");
              });
          });
        }
      });
    }

    // Run when DOM is ready
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initKudosButtons);
    } else {
      initKudosButtons();
    }
  })();
  {% end %}
})()
