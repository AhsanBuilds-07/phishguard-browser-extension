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

  function goBackToSafety() {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'about:blank';
    }
  }

  /**
   * Shows a discrete sticky floating badge after the user overrides a warning.
   */
  function showStickyBadge(report) {
    SentinelBlockPage.pill(report, () => {
      sessionStorage.removeItem(sessionDismissKey);
      showWarningOverlay(report);
    });
  }

  /**
   * Renders the full-screen block page in an isolated Shadow DOM.
   */
  function showWarningOverlay(report) {
    if (document.getElementById('sentinel-warning-overlay-host')) return;

    // If user previously overrode this origin in this session, show the sticky badge instead
    if (sessionStorage.getItem(sessionDismissKey)) {
      showStickyBadge(report);
      return;
    }

    // Lock password inputs while the block page is active
    togglePasswordInputs(true);

    SentinelBlockPage.show(report, {
      onLeave: goBackToSafety,
      onProceed: (close) => {
        // Reversible override: store in session, unlock inputs, show sticky badge
        sessionStorage.setItem(sessionDismissKey, 'true');
        togglePasswordInputs(false);
        close();
        showStickyBadge(report);

        // Inform background of user override
        try {
          chrome.runtime.sendMessage({
            action: 'SET_USER_OVERRIDE',
            hostname: currentHost,
            url: window.location.href
          });
        } catch (e) {}
      }
    });
  }

  /**
   * Renders a non-intrusive sticky top caution banner for suspicious sites.
   */
  function showTopWarningBanner(report) {
    SentinelBlockPage.banner(report, { onLeave: goBackToSafety });
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
