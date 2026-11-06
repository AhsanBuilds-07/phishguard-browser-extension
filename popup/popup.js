/**
 * SentinelAI: Phishing & Scam Link Shield
 * Popup Controller (Manifest V3)
 *
 * Reads directly from chrome.storage.local to display live threat score,
 * status badge, currently scanned URL, and flagged heuristics.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements
  const targetDomainEl = document.getElementById('target-domain');
  const targetUrlFullEl = document.getElementById('target-url-full');
  const protocolPillEl = document.getElementById('protocol-pill');

  const gaugeFillEl = document.getElementById('gauge-fill');
  const threatScoreEl = document.getElementById('threat-score');
  const statusBadgeEl = document.getElementById('status-badge');
  const statusTextEl = document.getElementById('status-text');
  const verdictSummaryEl = document.getElementById('verdict-summary');
  const modelNameEl = document.getElementById('model-name');
  const modelVersionEl = document.getElementById('model-version');
  const benignProbabilityEl = document.getElementById('benign-probability');
  const phishingProbabilityEl = document.getElementById('phishing-probability');
  const benignProbabilityBar = document.getElementById('benign-probability-bar');
  const phishingProbabilityBar = document.getElementById('phishing-probability-bar');

  const flagsBadgeEl = document.getElementById('flags-badge');
  const flagsListEl = document.getElementById('flags-list');

  const btnRescan = document.getElementById('btn-rescan');
  const rescanSpin = document.getElementById('rescan-spin');
  const btnWhitelist = document.getElementById('btn-whitelist');
  const whitelistLabel = document.getElementById('whitelist-label');

  let currentTabId = null;
  let currentAssessment = null;

  // SVG Gauge circumference: 2 * PI * 40 = 251.2
  const GAUGE_CIRCUMFERENCE = 251.2;

  /**
   * Animates the radial progress gauge.
   */
  function setGauge(percent, color) {
    if (!gaugeFillEl) return;
    const clamped = Math.max(0, Math.min(100, percent));
    const offset = GAUGE_CIRCUMFERENCE - (clamped / 100) * GAUGE_CIRCUMFERENCE;
    gaugeFillEl.style.strokeDashoffset = offset;
    gaugeFillEl.style.stroke = color;
  }

  /**
   * Renders the complete assessment report into the popup UI.
   */
  function renderReport(report) {
    currentAssessment = report;
    if (!report) return;

    // 1. Scanned URL & Domain
    const domain = report.hostname || 'Unknown Host';
    const fullUrl = report.url || domain;

    if (targetDomainEl) targetDomainEl.textContent = domain;
    if (targetUrlFullEl) targetUrlFullEl.textContent = fullUrl;

    // Protocol badge
    const isHttps = report.breakdown?.isHttps || (fullUrl.startsWith('https://'));
    if (protocolPillEl) {
      if (report.riskLevel === 'INTERNAL') {
        protocolPillEl.textContent = 'SYSTEM';
        protocolPillEl.className = 'pill pill-neutral';
      } else {
        protocolPillEl.textContent = isHttps ? 'HTTPS' : 'HTTP';
        protocolPillEl.className = isHttps ? 'pill pill-safe' : 'pill pill-danger';
      }
    }

    // 2. Score & Status Badge
    const riskPercent = Math.round((report.riskScore || 0) * 100);
    if (threatScoreEl) threatScoreEl.textContent = `${riskPercent}%`;
    const phishingProbability = Number(report.probabilities?.phishing ?? report.riskScore ?? 0);
    const benignProbability = Number(report.probabilities?.benign ?? (1 - phishingProbability));
    if (modelNameEl) modelNameEl.textContent = report.modelType || 'Trained Random Forest';
    if (modelVersionEl) modelVersionEl.textContent = report.modelVersion || 'No inference';
    if (benignProbabilityEl) benignProbabilityEl.textContent = `${(benignProbability * 100).toFixed(2)}%`;
    if (phishingProbabilityEl) phishingProbabilityEl.textContent = `${(phishingProbability * 100).toFixed(2)}%`;
    if (benignProbabilityBar) benignProbabilityBar.style.width = `${Math.max(0, Math.min(100, benignProbability * 100))}%`;
    if (phishingProbabilityBar) phishingProbabilityBar.style.width = `${Math.max(0, Math.min(100, phishingProbability * 100))}%`;

    // Whitelisted handling
    if (report.whitelisted) {
      setGauge(0, '#10b981');
      if (statusBadgeEl) statusBadgeEl.className = 'status-badge badge-safe';
      if (statusTextEl) statusTextEl.textContent = 'Trusted Domain';
      if (verdictSummaryEl) {
        verdictSummaryEl.textContent = 'This domain is on your personal trusted list. Protection alerts bypassed.';
      }
      updateWhitelistBtn(true);
      if (flagsBadgeEl) {
        flagsBadgeEl.textContent = 'Trusted';
        flagsBadgeEl.className = 'count-pill pill-zero';
      }
      if (flagsListEl) {
        flagsListEl.innerHTML = `
          <div class="clean-box">
            <div class="clean-text">
              <span class="clean-title">Domain Whitelisted by User</span>
              <span class="clean-desc">You marked this domain as trusted. Click "Trusted (Remove)" to re-enable security scanning.</span>
            </div>
          </div>
        `;
      }
      return;
    }

    updateWhitelistBtn(false);

    // Dynamic Verdict & Gauge Color
    if (report.riskLevel === 'RISK' || (report.riskScore > 0.75)) {
      setGauge(riskPercent, '#ef4444');
      if (statusBadgeEl) statusBadgeEl.className = 'status-badge badge-risk';
      if (statusTextEl) statusTextEl.textContent = 'High Risk Phishing';
      if (verdictSummaryEl) {
        verdictSummaryEl.textContent = report.statusText || 'Critical threat: High probability of credential theft or scam links.';
      }
    } else if (report.riskLevel === 'WARN' || (report.riskScore >= 0.40)) {
      setGauge(riskPercent, '#f59e0b');
      if (statusBadgeEl) statusBadgeEl.className = 'status-badge badge-warn';
      if (statusTextEl) statusTextEl.textContent = 'Suspicious Link';
      if (verdictSummaryEl) {
        verdictSummaryEl.textContent = report.statusText || 'Caution: Unusual domain characteristics or keywords detected.';
      }
    } else if (report.riskLevel === 'INTERNAL') {
      setGauge(0, '#10b981');
      if (statusBadgeEl) statusBadgeEl.className = 'status-badge badge-safe';
      if (statusTextEl) statusTextEl.textContent = 'Browser System';
      if (verdictSummaryEl) {
        verdictSummaryEl.textContent = 'Internal browser system page. Securely isolated in browser sandbox.';
      }
    } else {
      setGauge(riskPercent, '#10b981');
      if (statusBadgeEl) statusBadgeEl.className = 'status-badge badge-safe';
      if (statusTextEl) statusTextEl.textContent = 'Safe Site';
      if (verdictSummaryEl) {
        verdictSummaryEl.textContent = report.statusText || 'Clean URL structure: Zero deceptive phishing patterns detected.';
      }
    }

    // 3. Flags breakdown
    const flags = report.flags || [];
    if (flags.length === 0) {
      if (flagsBadgeEl) {
        flagsBadgeEl.textContent = '0 Detected';
        flagsBadgeEl.className = 'count-pill pill-zero';
      }
      if (flagsListEl) {
        flagsListEl.innerHTML = `
          <div class="clean-box">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
              <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            <div class="clean-text">
              <span class="clean-title">All URL checks passed</span>
              <span class="clean-desc">No deceptive keywords, raw IP address, or phishing tactics detected.</span>
            </div>
          </div>
        `;
      }
    } else {
      if (flagsBadgeEl) {
        flagsBadgeEl.textContent = `${flags.length} Flag${flags.length === 1 ? '' : 's'}`;
        flagsBadgeEl.className = 'count-pill pill-active';
      }
      if (flagsListEl) {
        flagsListEl.innerHTML = flags.map(flag => {
          const lower = flag.toLowerCase();
          const isCritical = lower.includes('ip address') || lower.includes('unencrypted') || lower.includes('@') || lower.includes('high-abuse');
          const rowClass = isCritical ? 'flag-item' : 'flag-item flag-warning';
          return `
            <div class="${rowClass}">
              <svg class="flag-icon-svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              <span>${escapeHtml(flag)}</span>
            </div>
          `;
        }).join('');
      }
    }
  }

  function updateWhitelistBtn(isWhitelisted) {
    if (!btnWhitelist || !whitelistLabel) return;
    if (isWhitelisted) {
      btnWhitelist.classList.add('is-whitelisted');
      whitelistLabel.textContent = 'Trusted (Remove)';
    } else {
      btnWhitelist.classList.remove('is-whitelisted');
      whitelistLabel.textContent = 'Trust Domain';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, (m) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[m]));
  }

  /**
   * Loads the scan report from chrome.storage.local for the active tab.
   */
  async function loadActiveReport() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabs || tabs.length === 0) return;

      currentTabId = tabs[0].id;

      // 1. Read directly from chrome.storage.local
      const storageKey = `tab_${currentTabId}`;
      const data = await chrome.storage.local.get([storageKey, 'last_scan_result']);

      if (data && data[storageKey]) {
        renderReport(data[storageKey]);
      } else if (data && data.last_scan_result) {
        renderReport(data.last_scan_result);
      } else {
        // Fallback: ask background service worker
        chrome.runtime.sendMessage({ action: 'GET_SCAN_DATA', tabId: currentTabId }, (res) => {
          if (res?.success && res.assessment) {
            renderReport(res.assessment);
          }
        });
      }
    } catch (err) {
      console.warn('[SentinelAI Popup] Init error:', err);
    }
  }

  // Real-time listener: updates popup dashboard if storage changes
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && currentTabId) {
      const key = `tab_${currentTabId}`;
      if (changes[key] && changes[key].newValue) {
        renderReport(changes[key].newValue);
      }
    }
  });

  // Re-scan Button
  if (btnRescan) {
    btnRescan.addEventListener('click', () => {
      if (!currentTabId) return;
      if (rescanSpin) rescanSpin.classList.add('spin-icon');
      btnRescan.disabled = true;

      chrome.runtime.sendMessage({ action: 'RESCAN_TAB', tabId: currentTabId }, (res) => {
        if (rescanSpin) rescanSpin.classList.remove('spin-icon');
        btnRescan.disabled = false;
        if (res?.success && res.assessment) {
          renderReport(res.assessment);
        }
      });
    });
  }

  // Whitelist Button
  if (btnWhitelist) {
    btnWhitelist.addEventListener('click', () => {
      if (!currentAssessment || !currentAssessment.hostname) return;
      const hostname = currentAssessment.hostname;
      const willWhitelist = !currentAssessment.whitelisted;

      chrome.runtime.sendMessage({
        action: 'TOGGLE_WHITELIST',
        hostname,
        whitelist: willWhitelist,
        tabId: currentTabId
      }, (res) => {
        if (res?.success) {
          currentAssessment.whitelisted = willWhitelist;
          renderReport(currentAssessment);
        }
      });
    });
  }

  const dashboardSync = document.getElementById('dashboard-sync');
  const openConsoleButton = document.getElementById('btn-open-console');

  if (dashboardSync) {
    chrome.storage.local.get(['sentinel_local_dashboard_sync'], (values) => {
      if (chrome.runtime.lastError) {
        console.warn('[SentinelAI Popup] Could not load dashboard sync preference:', chrome.runtime.lastError.message);
        return;
      }
      dashboardSync.checked = values.sentinel_local_dashboard_sync === true;
    });

    dashboardSync.addEventListener('change', () => {
      chrome.storage.local.set({ sentinel_local_dashboard_sync: dashboardSync.checked }, () => {
        if (chrome.runtime.lastError) {
          console.warn('[SentinelAI Popup] Could not save dashboard sync preference:', chrome.runtime.lastError.message);
          dashboardSync.checked = !dashboardSync.checked;
        }
      });
    });
  }

  if (openConsoleButton) {
    openConsoleButton.addEventListener('click', () => {
      chrome.tabs.create({ url: 'http://127.0.0.1:8000' }, () => {
        if (chrome.runtime.lastError) {
          console.warn('[SentinelAI Popup] Could not open the local security console:', chrome.runtime.lastError.message);
        }
      });
    });
  }

  // Initial load
  await loadActiveReport();
});
