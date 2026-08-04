// WebGuardian Tracker Detector Scanner
(function () {
  async function fetchTrackers() {
    try {
      const response = await fetch(chrome.runtime.getURL('rules/trackerList.json'));
      if (response.ok) {
        return await response.json();
      }
    } catch (err) {
      console.warn('WebGuardian trackerDetector: Failed to fetch rules/trackerList.json, using mock data:', err);
    }
    // Fallback mock data
    return [
      "google-analytics.com",
      "connect.facebook.net",
      "hotjar.com",
      "mixpanel.com",
      "doubleclick.net",
      "googlesyndication.com",
      "scorecardresearch.com",
      "adnxs.com",
      "rubiconproject.com",
      "pubmatic.com",
      "criteo.com",
      "quantserve.com",
      "amplitude.com",
      "segment.io",
      "crazyegg.com",
      "intercom.io",
      "optimizely.com",
      "clarity.ms",
      "ads-twitter.com",
      "adroll.com",
      "outbrain.com",
      "taboola.com",
      "matomo.org"
    ];
  }

  window.trackerDetector = {
    async scan() {
      try {
        const trackerDomains = await fetchTrackers();
        const scripts = document.querySelectorAll('script');
        const detectedTrackers = [];
        
        for (const script of scripts) {
          const src = script.getAttribute('src');
          if (!src) continue;
          
          let resolvedSrc;
          try {
            resolvedSrc = new URL(src, window.location.href).href;
          } catch (e) {
            resolvedSrc = src;
          }
          
          for (const domain of trackerDomains) {
            if (resolvedSrc.includes(domain)) {
              if (!detectedTrackers.includes(domain)) {
                detectedTrackers.push(domain);
              }
              break; // Matches one domain, continue to next script
            }
          }
        }
        
        // Calculate penalty score: e.g. 5 points per matched tracker, capped at 25.
        const penaltyScore = Math.min(detectedTrackers.length * 5, 25);
        
        return {
          penaltyScore,
          detectedTrackers
        };
      } catch (err) {
        console.error('WebGuardian trackerDetector scan error:', err);
        return {
          penaltyScore: 0,
          detectedTrackers: []
        };
      }
    }
  };
})();
