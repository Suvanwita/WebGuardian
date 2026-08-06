document.addEventListener('DOMContentLoaded', () => {
  const visitedWebsitesVal = document.getElementById('visited-websites-val');
  const trackersBlockedVal = document.getElementById('trackers-blocked-val');
  const securityScoreVal = document.getElementById('security-score-val');
  const securityScoreIcon = document.getElementById('security-score-icon');
  
  const historicalBody = document.getElementById('historical-body');
  const activeTabsList = document.getElementById('active-tabs-list');
  const btnClear = document.getElementById('btn-clear');

  function formatDate(dateStr) {
    const todayStr = new Date().toISOString().split('T')[0];
    if (dateStr === todayStr) return 'Today';
    
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    if (dateStr === yesterdayStr) return 'Yesterday';

    try {
      const date = new Date(dateStr);
      if (isNaN(date.getTime())) return dateStr;
      return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
    } catch (e) {
      return dateStr;
    }
  }

  function loadDashboardData() {
    chrome.storage.local.get(null, (result) => {
      const dailyStats = result.dailyStats || [];
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

      const todayStr = new Date().toISOString().split('T')[0];
      const todayRecord = dailyStats.find(item => item.date === todayStr) || {
        visitedWebsites: 0,
        trackersBlocked: 0,
        securityScore: 100
      };

      // Render Today's Report
      visitedWebsitesVal.textContent = todayRecord.visitedWebsites;
      trackersBlockedVal.textContent = todayRecord.trackersBlocked;
      securityScoreVal.textContent = `${todayRecord.securityScore}%`;

      // Update Security Score Card Icon style based on level
      securityScoreIcon.className = 'card-icon score';
      if (todayRecord.securityScore < 50) {
        securityScoreIcon.classList.add('danger');
      } else if (todayRecord.securityScore < 80) {
        securityScoreIcon.classList.add('warning');
      }

      // Render Historical Logs table (sort most recent first)
      historicalBody.innerHTML = '';
      if (dailyStats.length === 0) {
        historicalBody.innerHTML = '<tr><td colspan="4" class="no-data">No activity logged yet. Visit some websites to generate reports.</td></tr>';
      } else {
        const sortedStats = [...dailyStats].sort((a, b) => b.date.localeCompare(a.date));
        
        sortedStats.forEach(row => {
          const tr = document.createElement('tr');
          
          let scoreClass = 'green';
          if (row.securityScore < 50) {
            scoreClass = 'red';
          } else if (row.securityScore < 80) {
            scoreClass = 'yellow';
          }

          tr.innerHTML = `
            <td><strong>${formatDate(row.date)}</strong></td>
            <td>${row.visitedWebsites}</td>
            <td>${row.trackersBlocked}</td>
            <td><span class="badge-score ${scoreClass}">${row.securityScore}%</span></td>
          `;
          historicalBody.appendChild(tr);
        });
      }

      // Render Active Inspected Tabs list
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

  // Load initial data
  loadDashboardData();

  // Listen for changes in local storage to dynamically update stats
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local') {
      loadDashboardData();
    }
  });

  // Clear local storage logic
  btnClear.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all WebGuardian statistics and temporary storage?')) {
      chrome.storage.local.clear(() => {
        loadDashboardData();
      });
    }
  });
});
