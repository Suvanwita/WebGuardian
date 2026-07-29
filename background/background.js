import { hasIpAddress, isExcessivelyLong, hasExcessiveSubdomains } from '../utils/urlAnalyzer.js';
import { checkHomographAttack } from '../utils/levenshtein.js';

const MOCK_TRUSTED_DOMAINS = [
  'google.com',
  'paypal.com',
  'amazon.com',
  'apple.com',
  'microsoft.com',
  'facebook.com',
  'netflix.com'
];

// Listen for navigation commitments (main frame only)
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    const { tabId, url } = details;

    // Skip internal, configuration or system pages
    if (
      url.startsWith('chrome://') || 
      url.startsWith('chrome-extension://') || 
      url.startsWith('about:') ||
      url.startsWith('edge://')
    ) {
      chrome.storage.local.set({
        [`tab_${tabId}`]: {
          url,
          riskScore: 0,
          anomalies: [],
          updatedAt: Date.now()
        }
      });
      return;
    }

    try {
      const anomalies = [];
      let riskScore = 0;

      const isIp = hasIpAddress(url);
      const isLong = isExcessivelyLong(url);
      const isExcessiveSub = hasExcessiveSubdomains(url);

      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname;
      const isHomograph = checkHomographAttack(hostname, MOCK_TRUSTED_DOMAINS);

      if (isIp) {
        anomalies.push('IP_ADDRESS_HOST');
        riskScore += 50;
      }
      if (isHomograph) {
        anomalies.push('HOMOGRAPH_ATTACK');
        riskScore += 50;
      }
      if (isLong) {
        anomalies.push('EXCESSIVELY_LONG');
        riskScore += 10;
      }
      if (isExcessiveSub) {
        anomalies.push('EXCESSIVE_SUBDOMAINS');
        riskScore += 15;
      }

      const tabData = {
        url,
        riskScore: Math.min(riskScore, 100), // Cap the risk score at 100
        anomalies,
        updatedAt: Date.now()
      };

      chrome.storage.local.set({
        [`tab_${tabId}`]: tabData
      });

      console.log(`WebGuardian: Tab ${tabId} risk analysis complete.`, tabData);
    } catch (error) {
      console.error('WebGuardian: Error analyzing URL in background:', error);
    }
  }
});

// Clean up stored risk state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
});
