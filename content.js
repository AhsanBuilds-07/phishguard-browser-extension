/**
 * SentinelAI: Phishing & Scam Link Shield
 * Content Script (Manifest V3)
 *
 * Responsibilities:
 * 1. Safely locks DOM credential inputs (password fields) upon threat detection.
 * 2. Injects a modern, dark-mode full-screen warning overlay into an isolated Shadow DOM.
 * 3. Provides a prominent "Go Back to Safety" button to navigate away from scam links.
 * 4. Offers secondary "Proceed Anyway (Unsafe)" and "Trust Domain" controls.
 * 5. Displays a sticky top warning bar if the user chooses to bypass the full-screen modal.
 */

(() => {
  if (window.__sentinelAiInjected) return;
  window.__sentinelAiInjected = true;

  const currentHost = window.location.hostname.toLowerCase();
  const sessionDismissKey = `sentinel_dismissed_${currentHost}`;

  /**
   * Disables or re-enables form inputs to safeguard against credential harvesting.
   */
  function toggleInputsLock(locked) {
    const inputs = document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"], input[type="tel"]');
    inputs.forEach(input => {
      if (locked) {
        if (!input.hasAttribute('data-sentinel-locked')) {
          input.setAttribute('data-sentinel-locked', 'true');
          input.setAttribute('data-orig-disabled', input.disabled ? 'true' : 'false');
          input.setAttribute('data-orig-readonly', input.readOnly ? 'true' : 'false');
        }
        input.disabled = true;
        input.readOnly = true;
        input.blur();
      } else {
        if (input.hasAttribute('data-sentinel-locked')) {
          input.disabled = input.getAttribute('data-orig-disabled') === 'true';
          input.readOnly = input.getAttribute('data-orig-readonly') === 'true';
          input.removeAttribute('data-sentinel-locked');
          input.removeAttribute('data-orig-disabled');
          input.removeAttribute('data-orig-readonly');
        }
      }
    });
  }

  /**
   * Renders the isolated Shadow DOM Full-Screen Warning Overlay.
   */
  function showWarningOverlay(report) {
    if (document.getElementById('sentinel-warning-overlay-host')) return;

    // Check if dismissed for current origin in this browser tab session
    if (sessionStorage.getItem(sessionDismissKey)) {
      showTopWarningBanner(report);
      return;
    }

    // Safeguard user credentials
    toggleInputsLock(true);

    const hostDiv = document.createElement('div');
    hostDiv.id = 'sentinel-warning-overlay-host';
    const shadow = hostDiv.attachShadow({ mode: 'open' });

    const riskPercent = Math.round((report.riskScore ?? 0.95) * 100);
    const modelVersion = report.modelVersion || 'trained local model';
    const domainText = report.hostname || window.location.hostname;
    const flags = report.flags || [];

    const flagsHtml = flags.length > 0
      ? flags.map(flag => `
          <div class="threat-flag-row">
            <svg class="flag-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <span>${escapeHtml(flag)}</span>
          </div>
        `).join('')
      : `
          <div class="threat-flag-row">
            <svg class="flag-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
            <span>High-confidence deceptive scam heuristics matched</span>
          </div>
        `;

    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
          position: fixed !important;
          top: 0 !important;
          left: 0 !important;
          width: 100vw !important;
          height: 100vh !important;
          z-index: 2147483647 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          background: rgba(11, 15, 25, 0.96) !important;
          backdrop-filter: blur(16px) !important;
          -webkit-backdrop-filter: blur(16px) !important;
          animation: sentinelFadeIn 0.25s ease-out;
          color: #f1f5f9 !important;
          box-sizing: border-box !important;
        }

        @keyframes sentinelFadeIn {
          from { opacity: 0; transform: scale(0.97); }
          to { opacity: 1; transform: scale(1); }
        }

        .sentinel-modal {
          background: #111827;
          border: 1px solid rgba(239, 68, 68, 0.4);
          width: 92%;
          max-width: 580px;
          border-radius: 18px;
          box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.8), 0 0 30px rgba(239, 68, 68, 0.15);
          overflow: hidden;
          display: flex;
          flex-direction: column;
        }

        /* Modal Header */
        .modal-top {
          background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(185, 28, 28, 0.05) 100%);
          border-bottom: 1px solid rgba(239, 68, 68, 0.2);
          padding: 24px 28px;
          display: flex;
          align-items: center;
          gap: 16px;
        }

        .shield-badge {
          width: 50px;
          height: 50px;
          background: #ef4444;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
          color: #ffffff;
          box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4);
          animation: shieldPulse 2s infinite;
        }

        @keyframes shieldPulse {
          0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.5); }
          70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
          100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }

        .title-group h1 {
          margin: 0;
          font-size: 19px;
          font-weight: 800;
          color: #ffffff;
          letter-spacing: -0.01em;
        }

        .title-group p {
          margin: 4px 0 0 0;
          font-size: 13px;
          color: #94a3b8;
        }

        /* Modal Body */
        .modal-body {
          padding: 22px 28px;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .threat-summary-bar {
          background: rgba(30, 41, 59, 0.7);
          border: 1px solid #334155;
          border-radius: 12px;
          padding: 12px 16px;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }

        .target-host-info {
          display: flex;
          flex-direction: column;
        }

        .target-host-label {
          font-size: 10px;
          text-transform: uppercase;
          color: #94a3b8;
          font-weight: 700;
          letter-spacing: 0.05em;
        }

        .target-host-val {
          font-size: 14px;
          font-weight: 700;
          color: #38bdf8;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          word-break: break-all;
        }

        .risk-badge {
          background: #ef4444;
          color: #ffffff;
          font-size: 12px;
          font-weight: 800;
          padding: 6px 12px;
          border-radius: 9999px;
          letter-spacing: 0.02em;
          flex-shrink: 0;
        }

        .model-attribution {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          padding: 9px 12px;
          border: 1px solid rgba(56, 189, 248, 0.22);
          border-radius: 9px;
          background: rgba(14, 116, 144, 0.09);
          color: #a5c9d4;
          font-size: 10px;
        }

        .model-attribution strong {
          color: #7dd3fc;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-weight: 600;
        }

        .flags-header {
          font-size: 11px;
          font-weight: 700;
          text-transform: uppercase;
          color: #94a3b8;
          letter-spacing: 0.04em;
        }

        .flags-container {
          display: flex;
          flex-direction: column;
          gap: 8px;
          max-height: 160px;
          overflow-y: auto;
        }

        .threat-flag-row {
          background: rgba(15, 23, 42, 0.6);
          border: 1px solid rgba(239, 68, 68, 0.2);
          border-radius: 8px;
          padding: 9px 12px;
          display: flex;
          align-items: flex-start;
          gap: 10px;
          font-size: 12.5px;
          color: #cbd5e1;
          line-height: 1.4;
        }

        .flag-icon {
          flex-shrink: 0;
          margin-top: 1px;
        }

        .credentials-guard-box {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.25);
          border-radius: 10px;
          padding: 10px 14px;
          display: flex;
          align-items: center;
          gap: 10px;
          font-size: 12px;
          color: #fca5a5;
          font-weight: 600;
        }

        /* Modal Footer / Actions */
        .modal-footer {
          padding: 16px 28px 22px;
          background: #0f172a;
          border-top: 1px solid #1e293b;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }

        .btn {
          border: none;
          cursor: pointer;
          font-size: 13px;
          font-weight: 700;
          padding: 11px 18px;
          border-radius: 10px;
          transition: all 0.15s ease;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 6px;
          font-family: inherit;
        }

        /* Prominent Go Back to Safety Button */
        .btn-safety {
          background: #ef4444;
          color: #ffffff;
          box-shadow: 0 4px 12px rgba(239, 68, 68, 0.35);
        }

        .btn-safety:hover {
          background: #dc2626;
          transform: translateY(-1px);
          box-shadow: 0 6px 16px rgba(239, 68, 68, 0.45);
        }

        .btn-safety:active {
          transform: translateY(0);
        }

        .btn-bypass {
          background: transparent;
          color: #64748b;
          padding: 10px 12px;
        }

        .btn-bypass:hover {
          color: #cbd5e1;
          background: rgba(255, 255, 255, 0.05);
        }

        .btn-whitelist {
          background: transparent;
          color: #38bdf8;
          border: 1px solid #334155;
        }

        .btn-whitelist:hover {
          background: rgba(56, 189, 248, 0.1);
          border-color: #38bdf8;
        }
      </style>

      <div class="sentinel-modal">
        <div class="modal-top">
          <div class="shield-badge">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div class="title-group">
            <h1>High-risk URL detected</h1>
            <p>The trained SentinelAI model estimated a ${riskPercent}% phishing probability</p>
          </div>
        </div>

        <div class="modal-body">
          <div class="threat-summary-bar">
            <div class="target-host-info">
              <span class="target-host-label">Suspicious Host:</span>
              <span class="target-host-val">${escapeHtml(domainText)}</span>
            </div>
            <div class="risk-badge">${riskPercent}% Threat Risk</div>
          </div>

          <div class="model-attribution">
            <span>Random Forest · <strong>${escapeHtml(modelVersion)}</strong></span>
            <span>Local inference</span>
          </div>

          <div class="flags-header">Detected Risk Signals</div>
          <div class="flags-container">
            ${flagsHtml}
          </div>

          <div class="credentials-guard-box">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <span>Credential Guard Active: Input fields locked. Do NOT submit passwords or payments.</span>
          </div>
        </div>

        <div class="modal-footer">
          <button class="btn btn-bypass" id="btn-proceed">Proceed Anyway (Unsafe)</button>
          <div style="display: flex; gap: 8px;">
            <button class="btn btn-whitelist" id="btn-trust">Trust Domain</button>
            <button class="btn btn-safety" id="btn-safety">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
                <path d="M19 12H5M12 19l-7-7 7-7"/>
              </svg>
              Go Back to Safety
            </button>
          </div>
        </div>
      </div>
    `;

    document.documentElement.appendChild(hostDiv);

    // Primary: Go Back to Safety Button
    shadow.getElementById('btn-safety').addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'about:blank';
      }
    });

    // Secondary: Proceed Anyway
    shadow.getElementById('btn-proceed').addEventListener('click', () => {
      sessionStorage.setItem(sessionDismissKey, 'true');
      toggleInputsLock(false);
      hostDiv.remove();
      showTopWarningBanner(report);
    });

    // Whitelist Domain
    shadow.getElementById('btn-trust').addEventListener('click', () => {
      chrome.runtime.sendMessage({
        action: 'TOGGLE_WHITELIST',
        hostname: domainText,
        whitelist: true
      }, () => {
        toggleInputsLock(false);
        hostDiv.remove();
      });
    });
  }

  /**
   * Displays a persistent slim top banner if user explicitly bypasses the modal.
   */
  function showTopWarningBanner(report) {
    if (document.getElementById('sentinel-top-banner-host')) return;

    const bannerHost = document.createElement('div');
    bannerHost.id = 'sentinel-top-banner-host';
    const shadow = bannerHost.attachShadow({ mode: 'open' });
    const riskPercent = Math.round((report.riskScore ?? 0.95) * 100);

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
          background: #b91c1c !important;
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
          color: #b91c1c;
          border: none;
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
        }

        .banner-btn-safety:hover {
          background: #f8fafc;
        }

        .banner-btn-close {
          background: transparent;
          border: none;
          color: #ffffff;
          font-size: 16px;
          cursor: pointer;
          opacity: 0.8;
          margin-left: 8px;
        }

        .banner-btn-close:hover {
          opacity: 1;
        }
      </style>

      <div class="banner-left">
        <span>⚠ SentinelAI high-risk warning · ${riskPercent}% model probability. Do NOT enter credentials.</span>
      </div>

      <div style="display: flex; align-items: center;">
        <button class="banner-btn-safety" id="b-safety">Go Back to Safety</button>
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

  // Check assessment on injection
  try {
    chrome.runtime.sendMessage({ action: 'GET_SCAN_DATA' }, (res) => {
      if (res?.success && res.assessment) {
        if (res.assessment.riskScore > 0.75 && !res.assessment.whitelisted) {
          showWarningOverlay(res.assessment);
        }
      }
    });
  } catch (e) {}

  // Listen for background trigger
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'TRIGGER_WARNING_OVERLAY' && message.report) {
      showWarningOverlay(message.report);
      sendResponse({ success: true });
    }
  });
})();
