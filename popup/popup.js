document.addEventListener('DOMContentLoaded', () => {
  const scoreValue = document.getElementById('score-value');
  const scoreProgress = document.getElementById('score-progress');
  const riskStatus = document.getElementById('risk-status');
  const threatsList = document.getElementById('threats-list');
  const activeUrl = document.getElementById('active-url');
  const openDashboardBtn = document.getElementById('open-dashboard');

  const radius = 44;
  const circumference = 2 * Math.PI * radius;

  // Initialize SVG circle properties
  scoreProgress.style.strokeDasharray = `${circumference} ${circumference}`;
  scoreProgress.style.strokeDashoffset = circumference;

  // Query the active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length === 0) {
      activeUrl.textContent = 'None';
      return;
    }

    const activeTab = tabs[0];
    const tabId = activeTab.id;

    try {
      const urlObj = new URL(activeTab.url);
      activeUrl.textContent = urlObj.hostname;
    } catch (e) {
      activeUrl.textContent = activeTab.url || 'Unknown Host';
    }

    const storageKey = `tab_${tabId}`;
    chrome.storage.local.get([storageKey], (result) => {
      const tabData = result[storageKey] || {
        riskScore: 0,
        reasons: []
      };

      updatePopupUI(tabData.riskScore, tabData.reasons);
    });
  });

  function updatePopupUI(score, reasons) {
    // 1. Update score numerical value
    scoreValue.textContent = score;

    // 2. Update progress circle offset
    const offset = circumference - (Math.min(score, 100) / 100) * circumference;
    scoreProgress.style.strokeDashoffset = offset;

    // 3. Determine status text, color, and class based on score threshold
    let colorClass = 'safe';
    let riskLevel = 'Low Risk';
    let strokeColor = 'var(--color-green)';

    if (score >= 30 && score <= 70) {
      colorClass = 'warning';
      riskLevel = 'Suspicious';
      strokeColor = 'var(--color-yellow)';
    } else if (score > 70) {
      colorClass = 'danger';
      riskLevel = 'High Risk';
      strokeColor = 'var(--color-red)';
    }

    // Apply colors to risk level badge
    riskStatus.textContent = riskLevel;
    riskStatus.className = `risk-status ${colorClass}`;

    // Apply stroke color to dynamic progress path
    scoreProgress.style.stroke = strokeColor;

    // 4. Update the threats list
    threatsList.innerHTML = '';
    const activeReasons = reasons || [];

    if (activeReasons.length === 0) {
      const noThreatsEl = document.createElement('div');
      noThreatsEl.className = 'no-threats';
      noThreatsEl.innerHTML = `
        <div class="no-threats-icon">🛡️</div>
        <div>No threats detected. This page is safe.</div>
      `;
      threatsList.appendChild(noThreatsEl);
    } else {
      activeReasons.forEach(reason => {
        const item = document.createElement('div');
        item.className = 'threat-item';
        item.innerHTML = `
          <span class="threat-icon">⚠️</span>
          <span class="threat-name">${reason}</span>
        `;
        threatsList.appendChild(item);
      });
    }
  }

  // Dashboard navigation placeholder
  openDashboardBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
  });
});
