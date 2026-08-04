// WebGuardian Phishing Scanner
(function () {
  async function fetchKeywords() {
    try {
      const response = await fetch(chrome.runtime.getURL('rules/suspiciousKeywords.json'));
      if (response.ok) {
        return await response.json();
      }
    } catch (err) {
      console.warn('WebGuardian phishingScanner: Failed to fetch rules/suspiciousKeywords.json, using mock data:', err);
    }
    // Fallback mock data
    return [
      "verify", "wallet", "secure", "update", "account",
      "login", "signin", "password", "billing", "confirm",
      "support", "banking", "recovery", "auth", "credential",
      "security", "urgent", "suspended"
    ];
  }

  window.phishingScanner = {
    async scan() {
      try {
        const keywords = await fetchKeywords();
        const text = (document.body ? document.body.innerText : '').toLowerCase();
        
        let matchedCount = 0;
        const matchedKeywords = [];
        
        for (const keyword of keywords) {
          const lowerKeyword = keyword.toLowerCase();
          if (text.includes(lowerKeyword)) {
            matchedCount++;
            matchedKeywords.push(keyword);
          }
        }
        
        const penaltyScore = matchedCount * 5;
        return {
          penaltyScore,
          matchedKeywords
        };
      } catch (err) {
        console.error('WebGuardian phishingScanner scan error:', err);
        return {
          penaltyScore: 0,
          matchedKeywords: []
        };
      }
    }
  };
})();
