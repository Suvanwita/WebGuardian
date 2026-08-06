# 🛡️ WebGuardian

WebGuardian is a local-first, privacy-respecting Chrome Extension that provides proactive security monitoring and threat detection for your web browsing experience. It evaluates URL anomalies, header security policies, matches text content for phishing keywords, identifies external/insecure login forms, detects common tracking scripts, and evaluates password strength locally without sending any user data to remote servers.

---

## 🚀 Key Features

* **Real-time Threat Analysis**: Scores the risk of visited websites using multiple evaluation vectors.
* **Network & URL Security Checks**: Inspects hostnames for homograph attacks, IP-address hosts, excessively long subdomains, and verifies strict HTTPS response header policies.
* **DOM Content Scanners**:
  * **Phishing Keywords Scanner**: Scans visible page text for phishing triggers.
  * **Fake Login Form Detector**: Flags `<form>` tags with password fields pointing to external or insecure (`http://`) destinations.
  * **Tracker Script Detector**: Cross-references injected scripts against lists of common tracking domains.
* **Local Password Entropy Evaluation**: Attach strength meters to password input fields to label them as Weak, Medium, or Strong. **Evaluations occur entirely inside the browser tab context; password strings are never logged, stored, or sent anywhere.**
* **Security Indicators popup**: A sleek circular ring indicator highlighting the risk level of active pages.
* **Live Analytics Dashboard**: Displays cumulative daily statistics and charts real-time inspected browsing history using CSS Grid layouts.

---

## 📂 Project Architecture

```
WebGuardian/
├── manifest.json             # Extension manifest (MV3 configuration)
├── background/
│   └── background.js         # Service worker tracking headers, URLs, and stats
├── content/
│   ├── content.js            # Injected orchestrator coordination script
│   ├── phishing.js           # Phishing keyword scanner
│   ├── loginDetector.js      # Form destination verifier
│   ├── trackerDetector.js    # Third-party tracking script inspector
│   └── passwordChecker.js    # Local strength indicator
├── popup/
│   ├── popup.html            # Extension popup layout
│   ├── popup.css             # Dark themed popup styling
│   └── popup.js              # Active tab score viewer logic
├── dashboard/
│   ├── dashboard.html        # Analytics report manager dashboard
│   ├── dashboard.css         # Grid layouts dashboard styling
│   └── dashboard.js          # Live telemetry viewer & storage cleaner
├── rules/
│   ├── suspiciousKeywords.json # Phishing keyword dictionary
│   ├── trackerList.json      # Tracking script domains list
│   └── trustedDomains.json   # Trusted domains directory
└── utils/
    ├── urlAnalyzer.js        # Hostname/URL evaluation utilities
    ├── levenshtein.js        # Homograph attack checks (Levenshtein distance)
    ├── entropy.js            # Shannon entropy password calculations
    └── headers.js            # Security response headers validator
```

---

## 📊 Security Risk Scoring Rules

WebGuardian aggregates scores dynamically (max limit: 100%) based on these categories:

### 1. URL Inspection (Base Layer)
* **IP Address Host**: `+50` points (avoids domain-based trust).
* **Homograph Attack**: `+50` points (targets domains mimicking popular portals).
* **Excessively Long URL**: `+10` points (common obfuscation method).
* **Excessive Subdomains**: `+15` points.

### 2. Network Header Policies
* **Missing Content Security Policy (CSP)**: Adds penalty.
* **Missing HTTP Strict Transport Security (HSTS)**: Adds penalty.
* **Missing X-Frame-Options (Clickjacking Protection)**: Adds penalty.

### 3. DOM Analysis
* **Phishing Keywords Match**: `+5` points per unique matching keyword from [suspiciousKeywords.json](file:///home/user/Desktop/WebGuardian/rules/suspiciousKeywords.json).
* **Fake Login Form**: `+50` points if a form contains a password field but has an insecure action (`http://`) or targets a different hostname than the host domain.
* **Trackers Detected**: `+5` points per tracking domain found in page scripts (capped at `25`).

---

## 🔒 Privacy & Local Storage Schema

WebGuardian uses `chrome.storage.local` to store state. Under a given tab ID key `tab_${tabId}`, the following schema is logged temporarily during the tab's lifecycle:

```json
{
  "url": "https://example.com/login",
  "riskScore": 65,
  "contentRiskScore": 55,
  "anomalies": ["MISSING_CSP", "FAKE_LOGIN_FORM", "TRACKERS_DETECTED"],
  "reasons": ["Missing CSP", "Fake Login Detected", "Trackers Detected"],
  "detectedTrackers": ["google-analytics.com"],
  "updatedAt": 1785986421500
}
```

The extension also aggregates real-time browsing telemetry to log daily metrics without utilizing external analytics servers:

* `dailyStats`: Keeps a 30-day index of daily metrics:
  ```json
  [
    {
      "date": "2026-08-06",
      "visitedWebsites": 12,
      "trackersBlocked": 58,
      "securityScore": 94
    }
  ]
  ```

---

## 🛠️ Installation & Getting Started

1. Clone or download this repository to your local machine.
2. Open **Google Chrome** or any Chromium-based browser.
3. Navigate to `chrome://extensions/`.
4. Enable **Developer mode** using the toggle switch in the upper-right corner.
5. Click the **Load unpacked** button in the upper-left corner.
6. Select the root folder of this project (`WebGuardian`).
7. WebGuardian is now active and monitoring!

---

## 🧪 Verification

You can verify the syntax correctness of the extension source code by running:
```bash
node -c content/phishing.js content/loginDetector.js content/trackerDetector.js content/passwordChecker.js content/content.js background/background.js popup/popup.js dashboard/dashboard.js
```
All Javascript modules should compile with no syntax errors.
