// WebGuardian Login Detector Scanner
(function () {
  window.loginDetector = {
    scan() {
      try {
        const forms = document.querySelectorAll('form');
        let penaltyScore = 0;
        const flaggedForms = [];
        
        for (const form of forms) {
          const passwordInput = form.querySelector('input[type="password"]');
          if (!passwordInput) continue;
          
          let action = form.getAttribute('action');
          let actionUrl;
          
          try {
            // Resolve relative URLs against the document's base URI / window.location.href
            actionUrl = new URL(action || '', window.location.href);
          } catch (e) {
            console.warn('WebGuardian loginDetector: Invalid form action URL:', action, e);
            continue;
          }
          
          const isExternal = actionUrl.hostname !== window.location.hostname;
          const isHttp = actionUrl.protocol === 'http:';
          
          if (isExternal || isHttp) {
            penaltyScore = 50;
            flaggedForms.push({
              action: action || '',
              resolvedAction: actionUrl.href,
              isExternal,
              isHttp
            });
          }
        }
        
        return {
          penaltyScore,
          flaggedForms
        };
      } catch (err) {
        console.error('WebGuardian loginDetector scan error:', err);
        return {
          penaltyScore: 0,
          flaggedForms: []
        };
      }
    }
  };
})();
