/**
 * SentinelAI: Phishing & Scam Link Shield
 * Content Script (Manifest V3)
 *
 * Capabilities:
 * 1. Safely extracts DOM threat signals (form actions, password destinations, title claims)
 *    and reports them to the background service worker.
 * 2. Injects isolated Shadow DOM warning overlay with Scam Story & Evidence Breakdown.
 * 3. Provides clean, non-disruptive user controls:
 *    - "Go Back to Safety" (history.back / safe exit)
 *    - "I Understand the Risk — Proceed Anyway" (reversible override, persistent badge)
 *    - "Trust Domain" (whitelisting)
 * 4. Shows non-intrusive amber banner for suspicious links without locking forms.
 */

(() => {
  if (window.__sentinelAiInjected) return;
  window.__sentinelAiInjected = true;

  const currentHost = window.location.hostname.toLowerCase();
  const currentOrigin = window.location.origin;
  const sessionDismissKey = `sentinel_override_${currentHost}`;

  // ==========================================================================
  // 1. DOM Signal Extraction
  // ==========================================================================

  function extractDomThreatSignals() {
    try {
      const forms = Array.from(document.forms || []);
      const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
      const textInputs = Array.from(document.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"]'));

      let insecureForms = 0;
      const crossOriginFormDestinations = [];
      const ipFormDestinations = [];

      forms.forEach(form => {
        let actionUrl = '';
        try {
          actionUrl = form.action ? new URL(form.action, window.location.href).href : window.location.href;
        } catch (e) {
          actionUrl = form.action || '';
        }

        if (actionUrl) {
          try {
            const parsedAction = new URL(actionUrl);
            const actionHost = parsedAction.hostname.toLowerCase();

            // Check if HTTP submission on HTTPS page
            if (window.location.protocol === 'https:' && parsedAction.protocol === 'http:') {
              insecureForms++;
            }

            // Check if raw IP destination
            if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}/.test(actionHost)) {
              ipFormDestinations.push(actionHost);
            }

            // Check if cross-origin destination
            if (parsedAction.origin !== currentOrigin && !actionHost.endsWith('.' + currentHost)) {
              crossOriginFormDestinations.push(actionHost);
            }
          } catch (e) {}
        }
      });

      // Detect credit card indicators
      const hasCreditCardField = Boolean(
        document.querySelector('input[autocomplete*="cc-"], input[name*="card"], input[name*="cvv"], input[id*="cvv"]')
      );

      return {
        formCount: forms.length,
        passwordInputCount: passwordInputs.length,
        textInputCount: textInputs.length,
        insecureForms,
        crossOriginFormDestinations: Array.from(new Set(crossOriginFormDestinations)),
        ipFormDestinations: Array.from(new Set(ipFormDestinations)),
        hasCreditCardField,
        title: document.title || '',
        url: window.location.href
      };
    } catch (e) {
      return {
        formCount: 0,
        passwordInputCount: 0,
        textInputCount: 0,
        insecureForms: 0,
        crossOriginFormDestinations: [],
        ipFormDestinations: [],
        hasCreditCardField: false,
        title: document.title || '',
        url: window.location.href
      };
    }
  }

  // Send DOM signals to background service worker
  function reportDomSignals() {
    const domSignals = extractDomThreatSignals();
    try {
      chrome.runtime.sendMessage({
        action: 'REPORT_DOM_SIGNALS',
        domSignals
      }, (res) => {
        if (chrome.runtime.lastError) return;
        if (res?.success && res.assessment) {
          handleAssessment(res.assessment);
        }
      });
    } catch (e) {}
  }

  // ==========================================================================
  // 2. Safe Password Inputs Safeguard
  // ==========================================================================

  function togglePasswordInputs(locked) {
    const inputs = document.querySelectorAll('input[type="password"]');
    inputs.forEach(input => {
      if (locked) {
        if (!input.hasAttribute('data-sentinel-locked')) {
          input.setAttribute('data-sentinel-locked', 'true');
          input.setAttribute('data-orig-disabled', input.disabled ? 'true' : 'false');
        }
        input.disabled = true;
      } else {
        if (input.hasAttribute('data-sentinel-locked')) {
          input.disabled = input.getAttribute('data-orig-disabled') === 'true';
          input.removeAttribute('data-sentinel-locked');
          input.removeAttribute('data-orig-disabled');
        }
      }
    });
  }

  // ==========================================================================
  // 3. UI Warning Overlays
  // ==========================================================================

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
   * Shows a discrete sticky floating badge after the user overrides a warning.
   */
  function showStickyBadge(report) {
    if (document.getElementById('sentinel-sticky-badge-host')) return;

    const hostDiv = document.createElement('div');
    hostDiv.id = 'sentinel-sticky-badge-host';
    const shadow = hostDiv.attachShadow({ mode: 'open' });

    const riskScore = Math.round((report.riskScore ?? 0.8) * 100);

    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          position: fixed !important;
          bottom: 20px !important;
          right: 20px !important;
          z-index: 2147483647 !important;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        }
        .sentinel-pill {
          display: flex;
          align-items: center;
          gap: 8px;
          background: rgba(15, 23, 42, 0.95);
          color: #f8fafc;
          border: 1px solid #ef4444;
          padding: 8px 14px;
          border-radius: 9999px;
          font-size: 12px;
          font-weight: 600;
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
          cursor: pointer;
          transition: transform 0.2s, background 0.2s;
        }
        .sentinel-pill:hover {
          transform: translateY(-2px);
          background: #1e293b;
        }
        .sentinel-dot {
          width: 8px;
          height: 8px;
          background: #ef4444;
          border-radius: 50%;
          animation: pulse 2s infinite;
        }
        @keyframes pulse {
          0% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.4; transform: scale(1.2); }
          100% { opacity: 1; transform: scale(1); }
        }
      </style>
      <div class="sentinel-pill" id="badge-click" title="Click to review SentinelAI security warning">
        <span class="sentinel-dot"></span>
        <span>SentinelAI: Overridden (${riskScore}% Risk)</span>
      </div>
    `;

    document.documentElement.appendChild(hostDiv);
    shadow.getElementById('badge-click').addEventListener('click', () => {
      hostDiv.remove();
      sessionStorage.removeItem(sessionDismissKey);
      showWarningOverlay(report);
    });
  }

  /**
   * Renders the Full-Screen Security Warning Overlay in an isolated Shadow DOM.
   */
  function showWarningOverlay(report) {
    if (document.getElementById('sentinel-warning-overlay-host')) return;

    // If user previously overrode this origin in this session, show the sticky badge instead
    if (sessionStorage.getItem(sessionDismissKey)) {
      showStickyBadge(report);
      return;
    }

    // Lock password inputs while warning modal is active
    togglePasswordInputs(true);

    const hostDiv = document.createElement('div');
    hostDiv.id = 'sentinel-warning-overlay-host';
    const shadow = hostDiv.attachShadow({ mode: 'open' });

    const riskPercent = Math.round((report.riskScore ?? 0.95) * 100);
    const domainText = report.hostname || window.location.hostname;
    const modelVersion = report.modelVersion || 'SentinelAI RF Ensemble';

    const brandMatch = report.brandMatch;
    const attackChain = report.attackChain || {};
    const evidenceList = report.evidence || [];
    const coachTip = report.scamCoachTip || 'Never enter passwords on unverified sites.';

    const brandBadgeHtml = brandMatch
      ? `<div class="brand-alert-banner">
           <span class="brand-icon">⚠</span>
           <div>
             <strong>Deceptive Brand Impersonation Detected</strong>
             <p>This site appears to impersonate <strong>${escapeHtml(brandMatch)}</strong>, but is hosted on an unauthorized domain (<code>${escapeHtml(domainText)}</code>).</p>
           </div>
         </div>`
      : '';

    const factsHtml = (attackChain.observedFacts && attackChain.observedFacts.length > 0)
      ? attackChain.observedFacts.map(fact => `<li>${escapeHtml(fact)}</li>`).join('')
      : `<li>Suspicious URL pattern and deceptive hostname characteristics.</li>`;

    const evidenceHtml = evidenceList.slice(0, 4).map(item => `
      <div class="evidence-card">
        <div class="evidence-header">
          <span class="evidence-tag ${item.severity === 'high' ? 'tag-high' : 'tag-med'}">${escapeHtml(item.category)}</span>
          <span class="evidence-title">${escapeHtml(item.title)}</span>
        </div>
        <p class="evidence-detail">${escapeHtml(item.detail)}</p>
      </div>
    `).join('');

    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          position: fixed !important;
          top: 0 !important;
          left: 0 !important;
          width: 100vw !important;
          height: 100vh !important;
          z-index: 2147483647 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          background: rgba(5, 8, 16, 0.94) !important;
          backdrop-filter: blur(12px) !important;
          color: #f1f5f9 !important;
          padding: 20px !important;
          box-sizing: border-box !important;
          overflow-y: auto !important;
        }

        .modal-card {
          background: #0f172a;
          border: 1px solid rgba(239, 68, 68, 0.4);
          border-radius: 16px;
          max-width: 640px;
          width: 100%;
          padding: 32px;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 40px rgba(239, 68, 68, 0.15);
          box-sizing: border-box;
          animation: modalIn 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes modalIn {
          from { opacity: 0; transform: scale(0.96) translateY(10px); }
          to { opacity: 1; transform: scale(1) translateY(0); }
        }

        .header-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 20px;
        }

        .badge-threat {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          background: rgba(239, 68, 68, 0.15);
          border: 1px solid #ef4444;
          color: #fca5a5;
          padding: 4px 10px;
          border-radius: 9999px;
          font-size: 12px;
          font-weight: 700;
          letter-spacing: 0.5px;
        }

        .risk-gauge-tag {
          font-size: 13px;
          font-weight: 700;
          color: #ef4444;
        }

        h1 {
          font-size: 24px;
          font-weight: 800;
          color: #ffffff;
          margin: 0 0 8px 0;
          letter-spacing: -0.5px;
        }

        .subtitle {
          font-size: 14px;
          color: #94a3b8;
          line-height: 1.5;
          margin: 0 0 20px 0;
        }

        .domain-pill {
          background: #1e293b;
          color: #f8fafc;
          padding: 2px 8px;
          border-radius: 6px;
          font-family: monospace;
          word-break: break-all;
        }

        .brand-alert-banner {
          display: flex;
          gap: 12px;
          background: rgba(239, 68, 68, 0.12);
          border-left: 4px solid #ef4444;
          padding: 12px 14px;
          border-radius: 8px;
          margin-bottom: 20px;
          font-size: 13px;
        }
        .brand-alert-banner strong {
          color: #fca5a5;
          display: block;
          margin-bottom: 2px;
        }
        .brand-alert-banner p {
          margin: 0;
          color: #cbd5e1;
          line-height: 1.4;
        }

        .section-title {
          font-size: 12px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.8px;
          color: #64748b;
          margin: 16px 0 8px 0;
        }

        .facts-list {
          margin: 0 0 16px 0;
          padding-left: 20px;
          font-size: 13px;
          color: #cbd5e1;
          line-height: 1.6;
        }

        .evidence-grid {
          display: grid;
          gap: 8px;
          margin-bottom: 20px;
        }
        .evidence-card {
          background: #1e293b;
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-radius: 8px;
          padding: 10px 14px;
          font-size: 12px;
        }
        .evidence-header {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 4px;
        }
        .evidence-tag {
          font-size: 10px;
          font-weight: 700;
          padding: 2px 6px;
          border-radius: 4px;
          text-transform: uppercase;
        }
        .tag-high { background: #ef4444; color: #fff; }
        .tag-med { background: #f59e0b; color: #fff; }
        .evidence-title { font-weight: 600; color: #f8fafc; }
        .evidence-detail { margin: 0; color: #94a3b8; line-height: 1.4; }

        .coach-box {
          display: flex;
          align-items: center;
          gap: 10px;
          background: rgba(56, 189, 248, 0.08);
          border: 1px solid rgba(56, 189, 248, 0.25);
          color: #7dd3fc;
          padding: 10px 14px;
          border-radius: 8px;
          font-size: 12px;
          margin-bottom: 24px;
        }

        .actions-row {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
        }
        .btn-safety {
          flex: 1;
          background: #ef4444;
          color: #ffffff;
          border: none;
          padding: 12px 20px;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 700;
          cursor: pointer;
          transition: background 0.2s;
          text-align: center;
        }
        .btn-safety:hover { background: #dc2626; }

        .btn-override {
          background: transparent;
          color: #94a3b8;
          border: 1px solid #334155;
          padding: 12px 18px;
          border-radius: 8px;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: color 0.2s, border-color 0.2s;
        }
        .btn-override:hover { color: #f8fafc; border-color: #64748b; }

        .footer-note {
          display: flex;
          justify-content: space-between;
          font-size: 11px;
          color: #64748b;
          margin-top: 16px;
          border-top: 1px solid rgba(255, 255, 255, 0.05);
          padding-top: 12px;
        }
      </style>

      <div class="modal-card">
        <div class="header-row">
          <div class="badge-threat">
            <span>●</span>
            <span>HIGH-RISK PHISHING INTERCEPTED</span>
          </div>
          <span class="risk-gauge-tag">${riskPercent}% Threat Probability</span>
        </div>

        <h1>Deceptive Website Blocked</h1>
        <p class="subtitle">
          SentinelAI prevented credential input on <span class="domain-pill">${escapeHtml(domainText)}</span>. This site matches signatures of deceptive credential theft.
        </p>

        ${brandBadgeHtml}

        <div class="section-title">Observed Attack Facts</div>
        <ul class="facts-list">
          ${factsHtml}
        </ul>

        <div class="section-title">Verified Evidence</div>
        <div class="evidence-grid">
          ${evidenceHtml}
        </div>

        <div class="coach-box">
          <span>💡</span>
          <span>${escapeHtml(coachTip)}</span>
        </div>

        <div class="actions-row">
          <button class="btn-safety" id="btn-back">Go Back to Safety (Recommended)</button>
          <button class="btn-override" id="btn-proceed">Proceed Anyway (Unsafe)</button>
        </div>

        <div class="footer-note">
          <span>SentinelAI Local Model: ${escapeHtml(modelVersion)}</span>
          <span>Overrides are reversible anytime via popup</span>
        </div>
      </div>
    `;

    document.documentElement.appendChild(hostDiv);

    // Button Listeners
    shadow.getElementById('btn-back').addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'about:blank';
      }
    });

    shadow.getElementById('btn-proceed').addEventListener('click', () => {
      // Reversible override: store in session, unlock inputs, show sticky badge
      sessionStorage.setItem(sessionDismissKey, 'true');
      togglePasswordInputs(false);
      hostDiv.remove();
      showStickyBadge(report);

      // Inform background of user override
      try {
        chrome.runtime.sendMessage({
          action: 'SET_USER_OVERRIDE',
          hostname: currentHost,
          url: window.location.href
        });
      } catch (e) {}
    });
  }

  /**
   * Renders a non-intrusive sticky top warning banner for suspicious sites.
   */
  function showTopWarningBanner(report) {
    if (document.getElementById('sentinel-top-banner-host') || document.getElementById('sentinel-warning-overlay-host')) return;

    const bannerHost = document.createElement('div');
    bannerHost.id = 'sentinel-top-banner-host';
    const shadow = bannerHost.attachShadow({ mode: 'open' });
    const riskPercent = Math.round((report.riskScore ?? 0.5) * 100);

    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          position: fixed !important;
          top: 0 !important;
          left: 0 !important;
          width: 100% !important;
          z-index: 2147483646 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: space-between !important;
          background: #d97706 !important;
          color: #ffffff !important;
          padding: 8px 16px !important;
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4) !important;
          font-size: 13px !important;
          box-sizing: border-box !important;
        }

        .banner-left {
          display: flex;
          align-items: center;
          gap: 8px;
          font-weight: 600;
        }

        .banner-btn-safety {
          background: #ffffff;
          color: #b45309;
          border: none;
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
        }

        .banner-btn-close {
          background: transparent;
          border: none;
          color: #ffffff;
          font-size: 16px;
          cursor: pointer;
          opacity: 0.8;
          margin-left: 10px;
        }
      </style>

      <div class="banner-left">
        <span>⚠ SentinelAI Caution · ${riskPercent}% threat probability. Exercise caution before submitting credentials.</span>
      </div>

      <div style="display: flex; align-items: center;">
        <button class="banner-btn-safety" id="b-safety">Go Back</button>
        <button class="banner-btn-close" id="b-close" title="Dismiss">✕</button>
      </div>
    `;

    document.documentElement.appendChild(bannerHost);

    shadow.getElementById('b-safety').addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'about:blank';
      }
    });

    shadow.getElementById('b-close').addEventListener('click', () => {
      bannerHost.remove();
    });
  }

  function handleAssessment(assessment) {
    if (!assessment || assessment.whitelisted) return;

    if (assessment.verdict === 'malicious' || assessment.riskLevel === 'RISK') {
      showWarningOverlay(assessment);
    } else if (assessment.verdict === 'suspicious' || assessment.riskLevel === 'WARN') {
      showTopWarningBanner(assessment);
    }
  }

  // ==========================================================================
  // 4. Execution Lifecycle
  // ==========================================================================

  // Report initial DOM signals once document is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', reportDomSignals);
  } else {
    reportDomSignals();
  }

  // Check initial assessment from background
  try {
    chrome.runtime.sendMessage({ action: 'GET_SCAN_DATA' }, (res) => {
      if (res?.success && res.assessment) {
        handleAssessment(res.assessment);
      }
    });
  } catch (e) {}

  // Listen for real-time messages from background service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'TRIGGER_WARNING_OVERLAY' && message.report) {
      handleAssessment(message.report);
      sendResponse({ success: true });
    }
    if (message.action === 'EXTRACT_DOM_SIGNALS') {
      sendResponse({ success: true, domSignals: extractDomThreatSignals() });
    }
  });
})();
