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

function getReasons(data) {
  const reasons = [];
  const anomalies = data.anomalies || [];
  if (anomalies.includes('IP_ADDRESS_HOST')) reasons.push('IP Address Host');
  if (anomalies.includes('HOMOGRAPH_ATTACK')) reasons.push('Homograph Attack');
  if (anomalies.includes('EXCESSIVELY_LONG')) reasons.push('Excessively Long URL');
  if (anomalies.includes('EXCESSIVE_SUBDOMAINS')) reasons.push('Excessive Subdomains');
  if (anomalies.includes('MISSING_CSP')) reasons.push('Missing CSP');
  if (anomalies.includes('MISSING_HSTS')) reasons.push('Missing HSTS');
  if (anomalies.includes('MISSING_XFRAME')) reasons.push('Missing X-Frame-Options');
  if (anomalies.includes('SUSPICIOUS_KEYWORDS')) reasons.push('Suspicious Keywords Match');
  if (anomalies.includes('FAKE_LOGIN_FORM')) reasons.push('Fake Login Detected');
  if (anomalies.includes('TRACKERS_DETECTED')) reasons.push('Trackers Detected');
  return reasons;
}

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
          reasons: [],
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
        reasons: getReasons({ anomalies }),
        updatedAt: Date.now()
      };

      chrome.storage.local.set({
        [`tab_${tabId}`]: tabData
      }, () => {
        updateDailyStats(tabId, tabData);
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
          reasons: getReasons({ anomalies: newAnomalies }),
          updatedAt: Date.now()
        };

        chrome.storage.local.set({ [storageKey]: updatedData }, () => {
          updateDailyStats(details.tabId, updatedData);
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
  chrome.storage.local.get(['tabStatsHistory'], (result) => {
    const tabStatsHistory = result.tabStatsHistory || {};
    delete tabStatsHistory[tabId];
    chrome.storage.local.set({ tabStatsHistory });
  });
});

// Listen for message from content script containing DOM scan results
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'contentScanResult') {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    const phishingScan = request.phishingScan || {};
    const loginScan = request.loginScan || {};
    const trackerScan = request.trackerScan || {};

    const phishingScore = phishingScan.score || 0;
    const loginPenalty = loginScan.score || 0;
    const trackerScore = trackerScan.score || 0;
    const detectedTrackers = trackerScan.detectedTrackers || [];

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

      const activeTrackerScore = trackerScore || 0;
      if (activeTrackerScore > 0) {
        if (!newAnomalies.includes('TRACKERS_DETECTED')) {
          newAnomalies.push('TRACKERS_DETECTED');
        }
      } else {
        const index = newAnomalies.indexOf('TRACKERS_DETECTED');
        if (index > -1) {
          newAnomalies.splice(index, 1);
        }
      }

      // Track the previous content risk contribution to update the overall score properly without double-counting
      const prevContentRisk = currentData.contentRiskScore || 0;
      const newContentRisk = phishingScore + loginPenalty + activeTrackerScore;

      let newRiskScore = currentData.riskScore - prevContentRisk + newContentRisk;
      newRiskScore = Math.max(0, Math.min(newRiskScore, 100));

      const updatedData = {
        ...currentData,
        riskScore: newRiskScore,
        contentRiskScore: newContentRisk,
        anomalies: newAnomalies,
        reasons: getReasons({ anomalies: newAnomalies }),
        detectedTrackers: detectedTrackers || [],
        updatedAt: Date.now()
      };

      chrome.storage.local.set({ [storageKey]: updatedData }, () => {
        updateDailyStats(tabId, updatedData);
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

function updateDailyStats(tabId, tabData) {
  const todayStr = new Date().toISOString().split('T')[0];
  
  chrome.storage.local.get(['dailyStats', 'tabStatsHistory'], (result) => {
    let dailyStats = result.dailyStats || [];
    let tabStatsHistory = result.tabStatsHistory || {};
    
    const lastLogged = tabStatsHistory[tabId] || { url: '', trackersCount: 0, lastRiskScore: 0, hasRiskLogged: false };
    
    let todayRecord = dailyStats.find(item => item.date === todayStr);
    if (!todayRecord) {
      todayRecord = { date: todayStr, visitedWebsites: 0, trackersBlocked: 0, securityScore: 100, totalRiskScoreSum: 0, scoreCount: 0 };
      dailyStats.push(todayRecord);
    }
    
    // 1. Visited websites count
    if (tabData.url && tabData.url !== lastLogged.url) {
      todayRecord.visitedWebsites += 1;
      lastLogged.url = tabData.url;
    }
    
    // 2. Trackers blocked
    const currentTrackerCount = tabData.detectedTrackers ? tabData.detectedTrackers.length : 0;
    const newTrackers = Math.max(0, currentTrackerCount - lastLogged.trackersCount);
    if (newTrackers > 0) {
      todayRecord.trackersBlocked += newTrackers;
      lastLogged.trackersCount = currentTrackerCount;
    }
    
    // 3. Security score
    const newRisk = tabData.riskScore || 0;
    const oldRisk = lastLogged.lastRiskScore;
    
    if (lastLogged.hasRiskLogged) {
      todayRecord.totalRiskScoreSum = todayRecord.totalRiskScoreSum - oldRisk + newRisk;
    } else {
      todayRecord.totalRiskScoreSum += newRisk;
      todayRecord.scoreCount += 1;
      lastLogged.hasRiskLogged = true;
    }
    lastLogged.lastRiskScore = newRisk;
    
    const avgRisk = todayRecord.scoreCount > 0 ? (todayRecord.totalRiskScoreSum / todayRecord.scoreCount) : 0;
    todayRecord.securityScore = Math.max(0, Math.round(100 - avgRisk));
    
    tabStatsHistory[tabId] = lastLogged;
    
    // Keep only last 30 days of daily stats
    if (dailyStats.length > 30) {
      dailyStats = dailyStats.slice(-30);
    }
    
    chrome.storage.local.set({ dailyStats, tabStatsHistory });
  });
}
