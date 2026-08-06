document.addEventListener('DOMContentLoaded', () => {
  const visitedWebsitesVal = document.getElementById('visited-websites-val');
  const trackersBlockedVal = document.getElementById('trackers-blocked-val');
  const securityScoreVal = document.getElementById('security-score-val');
  const securityScoreIcon = document.getElementById('security-score-icon');
  
  const historicalBody = document.getElementById('historical-body');
  const activeTabsList = document.getElementById('active-tabs-list');
  const btnClear = document.getElementById('btn-clear');

  const MOCK_HISTORICAL_STATS = [
    { date: 'Yesterday', visitedWebsites: 28, trackersBlocked: 142, securityScore: 94 },
    { date: '2 days ago', visitedWebsites: 35, trackersBlocked: 198, securityScore: 89 },
    { date: '3 days ago', visitedWebsites: 19, trackersBlocked: 87, securityScore: 97 },
    { date: '4 days ago', visitedWebsites: 42, trackersBlocked: 215, securityScore: 92 },
    { date: '5 days ago', visitedWebsites: 31, trackersBlocked: 120, securityScore: 95 },
    { date: '6 days ago', visitedWebsites: 25, trackersBlocked: 94, securityScore: 96 }
  ];

  // Initialize and Seed mock stats if not present
  chrome.storage.local.get(['historicalStats'], (result) => {
    if (!result.historicalStats) {
      chrome.storage.local.set({ historicalStats: MOCK_HISTORICAL_STATS }, () => {
        loadDashboardData();
      });
    } else {
      loadDashboardData();
    }
  });

  function loadDashboardData() {
    chrome.storage.local.get(null, (result) => {
      const historicalStats = result.historicalStats || [];
      const activeTabs = [];

      // Extract all currently monitored active tabs (keys matching `tab_*`)
      Object.keys(result).forEach(key => {
        if (key.startsWith('tab_')) {
          activeTabs.push({
            id: key.replace('tab_', ''),
            ...result[key]
          });
        }
      });

      // 1. Compute Today's Stats from active tabs
      const todayVisitedCount = activeTabs.length;
      
      let todayTrackersBlocked = 0;
      activeTabs.forEach(tab => {
        if (tab.detectedTrackers && Array.isArray(tab.detectedTrackers)) {
          todayTrackersBlocked += tab.detectedTrackers.length;
        }
      });

      // Today's Security Score = 100 - average(activeTabRiskScores)
      let todaySecurityScore = 100;
      if (activeTabs.length > 0) {
        const totalRisk = activeTabs.reduce((sum, tab) => sum + (tab.riskScore || 0), 0);
        todaySecurityScore = Math.max(0, Math.round(100 - (totalRisk / activeTabs.length)));
      } else {
        // Fallback to high score if no active pages have been navigated since start
        todaySecurityScore = 100;
      }

      // Render Today's Report
      visitedWebsitesVal.textContent = todayVisitedCount;
      trackersBlockedVal.textContent = todayTrackersBlocked;
      securityScoreVal.textContent = `${todaySecurityScore}%`;

      // Update Security Score Card Icon style based on level
      securityScoreIcon.className = 'card-icon score';
      if (todaySecurityScore < 50) {
        securityScoreIcon.classList.add('danger');
      } else if (todaySecurityScore < 80) {
        securityScoreIcon.classList.add('warning');
      }

      // 2. Render Historical Logs table
      historicalBody.innerHTML = '';
      if (historicalStats.length === 0) {
        historicalBody.innerHTML = '<tr><td colspan="4" class="no-data">No historical data available.</td></tr>';
      } else {
        historicalStats.forEach(row => {
          const tr = document.createElement('tr');
          
          let scoreClass = 'green';
          if (row.securityScore < 50) {
            scoreClass = 'red';
          } else if (row.securityScore < 80) {
            scoreClass = 'yellow';
          }

          tr.innerHTML = `
            <td><strong>${row.date}</strong></td>
            <td>${row.visitedWebsites}</td>
            <td>${row.trackersBlocked}</td>
            <td><span class="badge-score ${scoreClass}">${row.securityScore}%</span></td>
          `;
          historicalBody.appendChild(tr);
        });
      }

      // 3. Render Active Inspected Tabs list
      activeTabsList.innerHTML = '';
      if (activeTabs.length === 0) {
        activeTabsList.innerHTML = '<div class="no-data">No active tabs monitored. Visit a website to see live safety indicators.</div>';
      } else {
        activeTabs.forEach(tab => {
          const item = document.createElement('div');
          item.className = 'active-tab-item';

          let hostname = 'Unknown Host';
          try {
            hostname = new URL(tab.url).hostname;
          } catch (e) {
            hostname = tab.url || 'Unknown Host';
          }

          const score = tab.riskScore || 0;
          let scoreColor = 'green';
          if (score >= 30 && score <= 70) {
            scoreColor = 'yellow';
          } else if (score > 70) {
            scoreColor = 'red';
          }

          item.innerHTML = `
            <div class="tab-meta">
              <span class="tab-domain" title="${hostname}">${hostname}</span>
              <span class="tab-url" title="${tab.url}">${tab.url}</span>
            </div>
            <div class="tab-score ${scoreColor}">${score}% Risk</div>
          `;
          activeTabsList.appendChild(item);
        });
      }
    });
  }

  // Clear local storage logic
  btnClear.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all WebGuardian statistics and temporary storage?')) {
      chrome.storage.local.clear(() => {
        // Refresh the page to reflect empty states
        loadDashboardData();
      });
    }
  });
});
