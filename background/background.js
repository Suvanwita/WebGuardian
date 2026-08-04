import { hasIpAddress, isExcessivelyLong, hasExcessiveSubdomains } from '../utils/urlAnalyzer.js';
import { checkHomographAttack } from '../utils/levenshtein.js';
import { analyzeHeaders } from '../utils/headers.js';

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

      console.log(`WebGuardian: Tab ${tabId} URL risk analysis complete.`, tabData);
    } catch (error) {
      console.error('WebGuardian: Error analyzing URL in background:', error);
    }
  }
});

// Listen for HTTP response headers targeting main_frame requests
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    // Only process main_frame requests for active tabs
    if (details.tabId === -1) return;

    try {
      const headerAnalysis = analyzeHeaders(details.responseHeaders);
      const headerPenalty = headerAnalysis.riskScore;

      const storageKey = `tab_${details.tabId}`;
      chrome.storage.local.get([storageKey], (result) => {
        const currentData = result[storageKey] || {
          url: details.url,
          riskScore: 0,
          anomalies: [],
          updatedAt: Date.now()
        };

        const newRiskScore = Math.min(currentData.riskScore + headerPenalty, 100);

        // Add missing security header anomalies
        const newAnomalies = [...currentData.anomalies];
        if (!headerAnalysis.hasCSP && !newAnomalies.includes('MISSING_CSP')) {
          newAnomalies.push('MISSING_CSP');
        }
        if (!headerAnalysis.hasHSTS && !newAnomalies.includes('MISSING_HSTS')) {
          newAnomalies.push('MISSING_HSTS');
        }
        if (!headerAnalysis.hasXFrame && !newAnomalies.includes('MISSING_XFRAME')) {
          newAnomalies.push('MISSING_XFRAME');
        }

        const updatedData = {
          ...currentData,
          riskScore: newRiskScore,
          anomalies: newAnomalies,
          updatedAt: Date.now()
        };

        chrome.storage.local.set({ [storageKey]: updatedData }, () => {
          console.log(`WebGuardian: Tab ${details.tabId} headers analysis complete.`, updatedData);
          
          // Warn the user immediately if risk score exceeds 80
          if (newRiskScore > 80) {
            chrome.notifications.create(`risk_warning_${details.tabId}`, {
              type: 'basic',
              iconUrl: '/popup/logo.png',
              title: '⚠️ High Security Risk Warning',
              message: `The website you visited (${new URL(details.url).hostname}) has an extremely high risk score of ${newRiskScore}%. Proceed with extreme caution!`,
              priority: 2
            });
          }
        });
      });
    } catch (error) {
      console.error('WebGuardian: Error analyzing response headers:', error);
    }
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders']
);

// Clean up stored risk state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
});

// Listen for message from content script containing DOM scan results
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'contentScanResult') {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    const { phishingScore, loginPenalty, matchedKeywords, flaggedForms } = request.data;
    const storageKey = `tab_${tabId}`;

    chrome.storage.local.get([storageKey], (result) => {
      const currentData = result[storageKey] || {
        url: sender.tab.url || '',
        riskScore: 0,
        anomalies: [],
        updatedAt: Date.now()
      };

      const newAnomalies = [...currentData.anomalies];

      // Update anomalies based on scans
      if (phishingScore > 0) {
        if (!newAnomalies.includes('SUSPICIOUS_KEYWORDS')) {
          newAnomalies.push('SUSPICIOUS_KEYWORDS');
        }
      } else {
        const index = newAnomalies.indexOf('SUSPICIOUS_KEYWORDS');
        if (index > -1) {
          newAnomalies.splice(index, 1);
        }
      }

      if (loginPenalty > 0) {
        if (!newAnomalies.includes('FAKE_LOGIN_FORM')) {
          newAnomalies.push('FAKE_LOGIN_FORM');
        }
      } else {
        const index = newAnomalies.indexOf('FAKE_LOGIN_FORM');
        if (index > -1) {
          newAnomalies.splice(index, 1);
        }
      }

      // Track the previous content risk contribution to update the overall score properly without double-counting
      const prevContentRisk = currentData.contentRiskScore || 0;
      const newContentRisk = phishingScore + loginPenalty;

      let newRiskScore = currentData.riskScore - prevContentRisk + newContentRisk;
      newRiskScore = Math.max(0, Math.min(newRiskScore, 100));

      const updatedData = {
        ...currentData,
        riskScore: newRiskScore,
        contentRiskScore: newContentRisk,
        anomalies: newAnomalies,
        updatedAt: Date.now()
      };

      chrome.storage.local.set({ [storageKey]: updatedData }, () => {
        console.log(`WebGuardian: Tab ${tabId} content scan analysis updated.`, updatedData);

        // Warn the user immediately if risk score exceeds 80
        if (newRiskScore > 80) {
          chrome.notifications.create(`risk_warning_${tabId}`, {
            type: 'basic',
            iconUrl: '/popup/logo.png',
            title: '⚠️ High Security Risk Warning',
            message: `The website you visited (${new URL(updatedData.url).hostname}) has an extremely high risk score of ${newRiskScore}%. Proceed with extreme caution!`,
            priority: 2
          });
        }
        sendResponse({ success: true, updatedData });
      });
    });
    return true; // Keep message channel open for async response
  }
});
