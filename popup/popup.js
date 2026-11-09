/**
 * SentinelAI: Phishing & Scam Link Shield
 * Popup Controller (Manifest V3)
 *
 * Reliably displays active tab threat assessment, calibrated confidence,
 * brand impersonation alerts, and provides 1-click access to the full Command Center.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements
  const targetDomainEl = document.getElementById('target-domain');
  const targetUrlFullEl = document.getElementById('target-url-full');
  const protocolPillEl = document.getElementById('protocol-pill');
  const brandPillEl = document.getElementById('brand-pill');

  const gaugeFillEl = document.getElementById('gauge-fill');
  const threatScoreEl = document.getElementById('threat-score');
  const statusBadgeEl = document.getElementById('status-badge');
  const statusTextEl = document.getElementById('status-text');
  const verdictSummaryEl = document.getElementById('verdict-summary');
  const confidenceLabelEl = document.getElementById('confidence-label');

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
  const openConsoleButton = document.getElementById('btn-open-console');

  let currentTabId = null;
  let currentAssessment = null;

  // SVG Gauge circumference: 2 * PI * 40 = 251.2
  const GAUGE_CIRCUMFERENCE = 251.2;

  function setGauge(percent, color) {
    if (!gaugeFillEl) return;
    const clamped = Math.max(0, Math.min(100, percent));
    const offset = GAUGE_CIRCUMFERENCE - (clamped / 100) * GAUGE_CIRCUMFERENCE;
    gaugeFillEl.style.strokeDashoffset = offset;
    gaugeFillEl.style.stroke = color;
  }

  function renderReport(report) {
    currentAssessment = report;
    if (!report) return;

    const domain = report.hostname || 'Unknown Host';
    const fullUrl = report.url || domain;

    if (targetDomainEl) targetDomainEl.textContent = domain;
    if (targetUrlFullEl) targetUrlFullEl.textContent = fullUrl;

    // Protocol and Brand Pills
    const isHttps = fullUrl.startsWith('https://');
    if (protocolPillEl) {
      if (report.riskLevel === 'INTERNAL') {
        protocolPillEl.textContent = 'SYSTEM';
        protocolPillEl.className = 'pill pill-neutral';
      } else {
        protocolPillEl.textContent = isHttps ? 'HTTPS' : 'HTTP';
        protocolPillEl.className = isHttps ? 'pill pill-safe' : 'pill pill-danger';
      }
    }

    if (brandPillEl) {
      if (report.brandMatch) {
        brandPillEl.textContent = `Impersonates: ${report.brandMatch}`;
        brandPillEl.classList.remove('hidden');
      } else {
        brandPillEl.classList.add('hidden');
      }
    }

    // Score & Gauge
    const riskPercent = Math.round((report.riskScore ?? 0) * 100);
    if (threatScoreEl) threatScoreEl.textContent = `${riskPercent}%`;

    const confidenceVal = Math.round((report.confidence ?? 0.85) * 100);
    if (confidenceLabelEl) confidenceLabelEl.textContent = `${confidenceVal}% Calibrated Confidence`;

    // Verdict styling
    const verdict = report.verdict || (report.riskScore >= 0.75 ? 'malicious' : report.riskScore >= 0.40 ? 'suspicious' : 'safe');

    if (statusBadgeEl && statusTextEl) {
      if (report.whitelisted || report.riskLevel === 'WHITELISTED') {
        statusBadgeEl.className = 'status-badge badge-safe';
        statusTextEl.textContent = 'Trusted Whitelist';
        setGauge(0, '#10b981');
      } else if (report.riskLevel === 'INTERNAL') {
        statusBadgeEl.className = 'status-badge badge-neutral';
        statusTextEl.textContent = 'System Page';
        setGauge(0, '#64748b');
      } else if (verdict === 'malicious') {
        statusBadgeEl.className = 'status-badge badge-danger';
        statusTextEl.textContent = 'Critical Risk';
        setGauge(riskPercent, '#ef4444');
      } else if (verdict === 'suspicious') {
        statusBadgeEl.className = 'status-badge badge-warning';
        statusTextEl.textContent = 'Suspicious Link';
        setGauge(riskPercent, '#f59e0b');
      } else if (verdict === 'unknown') {
        statusBadgeEl.className = 'status-badge badge-neutral';
        statusTextEl.textContent = 'Unknown Status';
        setGauge(riskPercent, '#64748b');
      } else {
        statusBadgeEl.className = 'status-badge badge-safe';
        statusTextEl.textContent = 'Safe Site';
        setGauge(riskPercent, '#10b981');
      }
    }

    if (verdictSummaryEl) {
      verdictSummaryEl.textContent = report.summary || report.statusText || 'Analysis complete.';
    }

    // Model details
    if (modelVersionEl) modelVersionEl.textContent = report.modelVersion || 'Local Random Forest';
    if (modelNameEl) modelNameEl.textContent = report.modelType || 'Random Forest Ensemble';

    const pBenign = report.probabilities?.benign ?? (1 - (report.riskScore || 0));
    const pPhish = report.probabilities?.phishing ?? (report.riskScore || 0);

    if (benignProbabilityEl) benignProbabilityEl.textContent = `${Math.round(pBenign * 100)}%`;
    if (phishingProbabilityEl) phishingProbabilityEl.textContent = `${Math.round(pPhish * 100)}%`;
    if (benignProbabilityBar) benignProbabilityBar.style.width = `${Math.round(pBenign * 100)}%`;
    if (phishingProbabilityBar) phishingProbabilityBar.style.width = `${Math.round(pPhish * 100)}%`;

    // Evidence & Flags
    const evidenceList = report.evidence || [];
    if (flagsBadgeEl) {
      flagsBadgeEl.textContent = `${evidenceList.length} Detected`;
      flagsBadgeEl.className = evidenceList.length > 0 ? 'count-pill pill-active' : 'count-pill pill-zero';
    }

    if (flagsListEl) {
      flagsListEl.innerHTML = '';
      if (evidenceList.length === 0) {
        flagsListEl.innerHTML = `
          <div class="clean-box">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.3">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
              <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            <div class="clean-text">
              <span class="clean-title">All checks normal</span>
              <span class="clean-desc">No deceptive brand signals, raw IP, or phishing tactics detected.</span>
            </div>
          </div>
        `;
      } else {
        evidenceList.forEach(item => {
          const row = document.createElement('div');
          row.className = 'flag-item';
          const isHigh = item.severity === 'high';
          const iconColor = isHigh ? '#ef4444' : '#f59e0b';
          const detailText = item.detail || (typeof item === 'string' ? item : item.title);

          row.innerHTML = `
            <svg class="flag-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2.2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <span class="flag-text">${escapeHtml(detailText)}</span>
          `;
          flagsListEl.appendChild(row);
        });
      }
    }

    // Whitelist button state
    if (whitelistLabel) {
      whitelistLabel.textContent = report.whitelisted ? 'Remove Trust' : 'Trust Domain';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, (m) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[m]));
  }

  /**
   * Loads assessment strictly for the active tab in current window.
   */
  async function loadActiveReport() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) {
        renderFallback('No active browser tab found.');
        return;
      }
      currentTabId = tab.id;

      chrome.runtime.sendMessage({ action: 'GET_SCAN_DATA', tabId: currentTabId }, (res) => {
        if (chrome.runtime.lastError) {
          renderFallback('Connecting to SentinelAI background engine...');
          return;
        }
        if (res?.success && res.assessment) {
          renderReport(res.assessment);
        } else {
          renderFallback('Waiting for page scan...');
        }
      });
    } catch (e) {
      renderFallback('Error querying browser tab.');
    }
  }

  function renderFallback(message) {
    if (verdictSummaryEl) verdictSummaryEl.textContent = message;
    if (threatScoreEl) threatScoreEl.textContent = '--';
  }

  // Re-scan button
  if (btnRescan) {
    btnRescan.addEventListener('click', () => {
      if (!currentTabId) return;
      if (rescanSpin) rescanSpin.classList.add('spinning');
      chrome.runtime.sendMessage({ action: 'RESCAN_TAB', tabId: currentTabId }, (res) => {
        setTimeout(() => {
          if (rescanSpin) rescanSpin.classList.remove('spinning');
          if (res?.success && res.assessment) {
            renderReport(res.assessment);
          }
        }, 300);
      });
    });
  }

  // Whitelist button
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

  // Open Command Center (uses chrome-extension URL so it works 100% offline without backend!)
  if (openConsoleButton) {
    openConsoleButton.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'OPEN_DASHBOARD', view: 'overview' });
    });
  }

  // Initial load
  await loadActiveReport();
});
