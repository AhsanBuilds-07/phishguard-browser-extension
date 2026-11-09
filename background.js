/**
 * SentinelAI: Phishing & Scam Link Shield
 * Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 * 1. Loads features, trained model, and multi-signal detector via importScripts.
 * 2. Manages tab-specific scan lifecycle with race-condition & de-duplication locks.
 * 3. Evaluates multi-signal pipeline: Lexical + ML probabilities + Homographs + Brands + DOM forms.
 * 4. Produces standardized verdicts: 'safe' | 'suspicious' | 'malicious' | 'unknown'.
 * 5. Updates tab badges and synchronizes scan history.
 * 6. Injects and communicates with content scripts.
 */

// Load core dependencies
if (typeof importScripts === 'function') {
  try {
    importScripts('ml/features.js', 'ml/models/model_exported.js', 'ml/detector.js');
  } catch (err) {
    console.error('[SentinelAI] Failed to importScripts:', err);
  }
}

const featureAPI = typeof SentinelFeatures !== 'undefined'
  ? SentinelFeatures
  : (typeof require === 'function' ? require('./ml/features.js') : null);

const modelAPI = typeof SentinelModel !== 'undefined'
  ? SentinelModel
  : (typeof require === 'function' ? require('./ml/models/model_exported.js') : null);

const detectorAPI = typeof SentinelDetector !== 'undefined'
  ? SentinelDetector
  : (typeof require === 'function' ? require('./ml/detector.js') : null);

const ACTIVE_MODEL_VERSION = modelAPI?.MODEL_VERSION || 'rf-20261104-183213';
const MAX_SCAN_HISTORY = 100;

// Tab caching and race-condition deduplication tracking
const tabCache = new Map();
const inFlightScans = new Map(); // tabId -> Promise
const lastAnalyzedUrlByTab = new Map(); // tabId -> url
const tabScanSequences = new Map(); // tabId -> sequence number

// ============================================================================
// Storage Utilities
// ============================================================================

function getStorage(key, defaultValue = null) {
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (res) => {
      if (chrome.runtime.lastError) {
        resolve(defaultValue);
      } else {
        resolve(res && res[key] !== undefined ? res[key] : defaultValue);
      }
    });
  });
}

function setStorage(key, value) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [key]: value }, () => resolve());
  });
}

async function isWhitelisted(hostname) {
  if (!hostname) return false;
  const list = await getStorage('sentinel_whitelist', []);
  const clean = hostname.toLowerCase();
  return list.some(d => clean === d || clean.endsWith('.' + d));
}

function isInternalUrl(url) {
  if (!url) return true;
  return (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('edge://') ||
    url.startsWith('about:') ||
    url.startsWith('devtools://') ||
    url.startsWith('view-source:') ||
    url.startsWith('data:') ||
    url.startsWith('blob:')
  );
}

// ============================================================================
// Multi-Signal URL Investigation Engine
// ============================================================================

/**
 * Extracts the canonical 14-feature vector matching ml/features.py and ml/features.js.
 */
function extractUrlFeatures(rawUrl) {
  let clean = (rawUrl || '').trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(clean)) clean = 'http://' + clean;
  let hostname = '';
  try { hostname = new URL(clean).hostname; } catch (e) {}
  const featureArray = featureAPI.extractFeatures(clean);
  const features = featureAPI.extractFeaturesDict(clean);
  return {
    featureArray,
    features,
    breakdown: { hostname }
  };
}

/**
 * Investigates a raw URL using canonical feature extraction, trained model inference,
 * and the multi-signal detection engine.
 *
 * @param {string} rawUrl
 * @param {Object} [domSignals]
 * @returns {Object} Complete standardized verdict report
 */
function investigateUrl(rawUrl, domSignals = null) {
  if (!featureAPI || !modelAPI || !detectorAPI) {
    throw new Error('SentinelAI core detection modules are unavailable.');
  }

  let cleanUrl = (rawUrl || '').trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(cleanUrl)) {
    cleanUrl = `http://${cleanUrl}`;
  }

  let hostname = '';
  try {
    const parsed = new URL(cleanUrl);
    hostname = (parsed.hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  } catch (e) {
    throw new Error('Enter a valid HTTP or HTTPS URL to investigate.');
  }

  if (!hostname) {
    throw new Error('URL must contain a valid hostname.');
  }

  // 1. Extract canonical 14 features
  const featureArray = featureAPI.extractFeatures(cleanUrl);
  const featureObj = featureAPI.extractFeaturesDict(cleanUrl);

  // 2. Compute rule-based lexical flags
  const lexicalFlags = [];
  if (featureObj.has_ip === 1) lexicalFlags.push('Raw IP address used instead of domain name');
  if (featureObj.has_at_symbol === 1) lexicalFlags.push('Contains "@" credential-masking delimiter');
  if (featureObj.is_https === 0) lexicalFlags.push('Unencrypted connection (insecure HTTP scheme)');
  if (featureObj.has_suspicious_tld === 1) lexicalFlags.push('High-abuse Top-Level Domain commonly used in phishing');
  if (featureObj.num_suspicious_keywords > 0) lexicalFlags.push(`Authentication or banking keywords detected (${featureObj.num_suspicious_keywords} matches)`);
  if (featureObj.num_subdomains >= 2) lexicalFlags.push(`Excessive subdomain depth (${featureObj.num_subdomains} levels)`);
  if (featureObj.num_hyphens >= 2) lexicalFlags.push(`Excessive hyphens in hostname (${featureObj.num_hyphens}) - typosquatting signal`);
  if (featureObj.domain_entropy > 3.5) lexicalFlags.push(`High algorithmic domain randomness (Entropy: ${featureObj.domain_entropy})`);
  if (featureObj.has_double_slash_in_path === 1) lexicalFlags.push('Open redirection path evasion pattern (//)');

  // 3. Execute Scikit-Learn Model Inference
  const mlProbabilities = modelAPI.predictProba(featureArray);
  const rawModelPhishingScore = Number(mlProbabilities[1].toFixed(4));

  // 4. Run Multi-Signal Engine (Homographs + Brand Impersonation + DOM + Scam Story)
  const report = detectorAPI.evaluateUrlSignals({
    url: cleanUrl,
    hostname,
    features: featureArray,
    mlProbabilities,
    lexicalFlags,
    domSignals,
    isWhitelisted: false,
    modelVersion: modelAPI.MODEL_VERSION || ACTIVE_MODEL_VERSION
  });

  // Attach raw features, probabilities, and model attributes
  report.features = featureObj;
  report.featureArray = featureArray;
  report.featureSchema = modelAPI.FEATURE_NAMES;
  report.modelVersion = modelAPI.MODEL_VERSION || ACTIVE_MODEL_VERSION;
  report.probabilities = { benign: mlProbabilities[0], phishing: mlProbabilities[1] };
  report.riskScore = rawModelPhishingScore; // Raw model probability score matching Scikit-Learn
  report.url = cleanUrl;
  report.hostname = hostname;

  return report;
}

async function saveScanHistory(report) {
  if (typeof chrome === 'undefined' || !chrome.storage) return;
  const history = await getStorage('sentinel_scan_history', []);
  const cleanItem = {
    url: report.url,
    hostname: report.hostname,
    verdict: report.verdict,
    riskLevel: report.riskLevel,
    riskScore: report.riskScore,
    confidence: report.confidence,
    brandMatch: report.brandMatch,
    summary: report.summary,
    timestamp: report.timestamp || Date.now()
  };
  const next = [cleanItem, ...history.filter(item => item.url !== report.url)].slice(0, MAX_SCAN_HISTORY);
  await setStorage('sentinel_scan_history', next);
}

async function syncLocalDashboard(report) {
  const enabled = await getStorage('sentinel_local_dashboard_sync', false);
  if (enabled !== true) return;

  try {
    await fetch('http://127.0.0.1:8000/api/extension-events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: report.url })
    });
  } catch (e) {
    // Local API not running; fail silently
  }
}

// ============================================================================
// Badge Visualizer
// ============================================================================

function updateBadge(tabId, verdict, riskLevel) {
  if (!tabId || typeof chrome === 'undefined' || !chrome.action) return;

  if (verdict === 'internal' || riskLevel === 'INTERNAL') {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }
  if (riskLevel === 'WHITELISTED') {
    chrome.action.setBadgeText({ tabId, text: 'SAFE' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' });
    return;
  }
  if (verdict === 'malicious' || riskLevel === 'RISK') {
    chrome.action.setBadgeText({ tabId, text: 'RISK' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#EF4444' });
    return;
  }
  if (verdict === 'suspicious' || riskLevel === 'WARN') {
    chrome.action.setBadgeText({ tabId, text: 'WARN' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#F59E0B' });
    return;
  }
  if (verdict === 'unknown') {
    chrome.action.setBadgeText({ tabId, text: 'UNKN' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748B' });
    return;
  }

  // Default Safe
  chrome.action.setBadgeText({ tabId, text: 'SAFE' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' });
}

// ============================================================================
// Core Tab Analysis Pipeline (Deduplicated & Race-Free)
// ============================================================================

/**
 * Analyzes a tab's URL with strict deduplication and out-of-order race protection.
 */
async function analyzeTab(tabId, url, domSignals = null) {
  if (!tabId) return null;

  // Handle internal browser URLs
  if (!url || isInternalUrl(url)) {
    const internalReport = {
      tabId,
      url: url || 'Browser Page',
      hostname: 'System Page',
      verdict: 'safe',
      riskLevel: 'INTERNAL',
      riskScore: 0.0,
      confidence: 1.0,
      summary: 'Internal browser page. Isolated from network threats.',
      evidence: [],
      timestamp: Date.now()
    };
    tabCache.set(tabId, internalReport);
    updateBadge(tabId, 'internal', 'INTERNAL');
    await setStorage(`tab_${tabId}`, internalReport);
    return internalReport;
  }

  // Deduplication check: if the exact same URL was just analyzed and no new DOM signals provided, return cached
  const lastUrl = lastAnalyzedUrlByTab.get(tabId);
  const cachedReport = tabCache.get(tabId);
  if (lastUrl === url && cachedReport && !domSignals) {
    return cachedReport;
  }

  // Set sequence number for this tab
  const currentSeq = (tabScanSequences.get(tabId) || 0) + 1;
  tabScanSequences.set(tabId, currentSeq);
  lastAnalyzedUrlByTab.set(tabId, url);

  try {
    // 1. Check user whitelist
    let hostname = '';
    try {
      hostname = new URL(url).hostname;
    } catch (e) {}

    const whitelisted = await isWhitelisted(hostname);
    if (whitelisted) {
      const whiteReport = {
        tabId,
        url,
        hostname,
        verdict: 'safe',
        riskLevel: 'WHITELISTED',
        riskScore: 0.0,
        confidence: 1.0,
        whitelisted: true,
        summary: 'Trusted Domain. Added to personal whitelist.',
        evidence: [{ category: 'User Preference', title: 'Whitelist', detail: 'Domain is explicitly trusted by user.', severity: 'low' }],
        modelVersion: ACTIVE_MODEL_VERSION,
        timestamp: Date.now()
      };
      if (tabScanSequences.get(tabId) === currentSeq) {
        tabCache.set(tabId, whiteReport);
        updateBadge(tabId, 'safe', 'WHITELISTED');
        await setStorage(`tab_${tabId}`, whiteReport);
      }
      return whiteReport;
    }

    // 2. Scan Quota & Token Limit Verification
    const activeUser = await getStorage('sentinel_user', null);
    if (!activeUser) {
      // Guest / Unregistered user: Allowed exactly 1 website scan
      const guestScans = await getStorage('sentinel_guest_scans', 0);
      if (guestScans >= 1) {
        const guestLimitReport = {
          tabId,
          url,
          hostname,
          verdict: 'unknown',
          riskLevel: 'AUTH',
          riskScore: 0.0,
          confidence: 1.0,
          guestLimit: true,
          summary: 'Guest scan limit reached (1/1 website scanned). Redirecting to login to unlock full protection.',
          evidence: [
            { category: 'Access Control', title: '1-Scan Guest Limit', detail: 'Unregistered users can scan 1 website free. Sign in or register to continue scanning.', severity: 'medium' }
          ],
          modelVersion: ACTIVE_MODEL_VERSION,
          timestamp: Date.now()
        };
        tabCache.set(tabId, guestLimitReport);
        chrome.action.setBadgeText({ tabId, text: 'AUTH' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#6366F1' });
        await setStorage(`tab_${tabId}`, guestLimitReport);

        // Auto-navigate to auth page after 1 scan used
        try {
          if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.update) {
            chrome.tabs.update(tabId, { url: 'http://127.0.0.1:8000/auth.html?reason=guest_limit' });
          }
        } catch (e) {}
        return guestLimitReport;
      }
    } else {
      // User is logged in: Check demo quota
      const isDemo = activeUser.email === 'demo@sentinelai.security' || activeUser.account_tier === 'demo';
      if (isDemo) {
        const demoScans = await getStorage('sentinel_demo_scans', activeUser.scans_used || 0);
        if (demoScans >= 5) {
          const demoLimitReport = {
            tabId,
            url,
            hostname,
            verdict: 'unknown',
            riskLevel: 'LOCK',
            riskScore: 0.0,
            confidence: 1.0,
            demoLimit: true,
            summary: 'Demo account only allows 5 tokens. For further protection, please login with your personal ID.',
            evidence: [
              { category: 'Account Quota', title: '5-Token Demo Limit', detail: 'Demo operator account is limited to 5 free scans. Login with your personal account for full access.', severity: 'high' }
            ],
            modelVersion: ACTIVE_MODEL_VERSION,
            timestamp: Date.now()
          };
          tabCache.set(tabId, demoLimitReport);
          chrome.action.setBadgeText({ tabId, text: 'LOCK' });
          chrome.action.setBadgeBackgroundColor({ tabId, color: '#EF4444' });
          await setStorage(`tab_${tabId}`, demoLimitReport);
          return demoLimitReport;
        }
      }
    }

    // 3. Perform investigation
    const report = investigateUrl(url, domSignals);
    report.tabId = tabId;

    // Record token consumption
    if (!activeUser) {
      const currentGuest = await getStorage('sentinel_guest_scans', 0);
      await setStorage('sentinel_guest_scans', currentGuest + 1);
      report.tokenQuota = { tier: 'guest', used: currentGuest + 1, limit: 1, remaining: Math.max(0, 1 - (currentGuest + 1)) };
    } else if (activeUser.email === 'demo@sentinelai.security' || activeUser.account_tier === 'demo') {
      const currentDemo = await getStorage('sentinel_demo_scans', 0);
      await setStorage('sentinel_demo_scans', currentDemo + 1);
      report.tokenQuota = { tier: 'demo', used: currentDemo + 1, limit: 5, remaining: Math.max(0, 5 - (currentDemo + 1)) };
    } else {
      report.tokenQuota = { tier: activeUser.account_tier || 'personal', used: activeUser.scans_used || 0, limit: activeUser.scan_tokens || 50, remaining: 50 };
    }

    // Check if user previously overrode this origin in extension storage
    const userOverrides = await getStorage('sentinel_overrides', []);
    if (userOverrides.includes(report.hostname)) {
      report.overridden = true;
    }

    // Verify sequence before committing state (guards against out-of-order race conditions)
    if (tabScanSequences.get(tabId) === currentSeq) {
      tabCache.set(tabId, report);
      updateBadge(tabId, report.verdict, report.riskLevel);
      await setStorage(`tab_${tabId}`, report);
      await saveScanHistory(report);
      void syncLocalDashboard(report);

      // Inject content script and dispatch warning if malicious
      if (report.verdict === 'malicious' && !report.overridden) {
        try {
          await chrome.scripting.executeScript({
            target: { tabId },
            files: ['content.js']
          });
        } catch (e) {}

        chrome.tabs.sendMessage(tabId, {
          action: 'TRIGGER_WARNING_OVERLAY',
          report
        }).catch(() => {});
      }
    }

    return report;
  } catch (err) {
    console.error(`[SentinelAI] Error analyzing tab ${tabId}:`, err);
    return null;
  }
}

// ============================================================================
// Event Listeners (WebNavigation, Tabs, Runtime Messages)
// ============================================================================

if (typeof chrome !== 'undefined') {
  // 1. webNavigation.onCompleted (Primary commit listener for main frame)
  chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId === 0 && details.url) {
      analyzeTab(details.tabId, details.url);
    }
  });

  // 2. tabs.onUpdated (Fallback for dynamic client-side SPA routing)
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
      analyzeTab(tabId, changeInfo.url);
    }
  });

  // 3. tabs.onActivated (Synchronize badge upon switching tabs)
  chrome.tabs.onActivated.addListener(async (activeInfo) => {
    const cached = tabCache.get(activeInfo.tabId);
    if (cached) {
      updateBadge(activeInfo.tabId, cached.verdict, cached.riskLevel);
    } else {
      try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (tab && tab.url) {
          analyzeTab(activeInfo.tabId, tab.url);
        }
      } catch (e) {}
    }
  });

  // 4. tabs.onRemoved (Cleanup tab-specific caches)
  chrome.tabs.onRemoved.addListener((tabId) => {
    tabCache.delete(tabId);
    lastAnalyzedUrlByTab.delete(tabId);
    tabScanSequences.delete(tabId);
    chrome.storage.local.remove([`tab_${tabId}`], () => {});
  });

  // ============================================================================
  // Message Passing Hub
  // ============================================================================

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const senderTabId = sender?.tab?.id;

    // Investigate arbitrary URL without navigation
    if (message.action === 'INVESTIGATE_URL') {
      try {
        const report = investigateUrl(message.url || '');
        saveScanHistory(report).then(() => {
          sendResponse({ success: true, report });
        });
      } catch (error) {
        sendResponse({ success: false, error: error.message });
      }
      return true;
    }

    // Report DOM threat signals from content script
    if (message.action === 'REPORT_DOM_SIGNALS') {
      const tabId = senderTabId;
      if (tabId && message.domSignals?.url) {
        analyzeTab(tabId, message.domSignals.url, message.domSignals).then((assessment) => {
          sendResponse({ success: true, assessment });
        });
        return true;
      }
      sendResponse({ success: false, error: 'Missing tab or URL' });
      return false;
    }

    // Set user override for a domain
    if (message.action === 'SET_USER_OVERRIDE') {
      const hostname = message.hostname;
      if (hostname) {
        getStorage('sentinel_overrides', []).then(async (overrides) => {
          if (!overrides.includes(hostname)) {
            overrides.push(hostname);
            await setStorage('sentinel_overrides', overrides);
          }
          sendResponse({ success: true, overrides });
        });
        return true;
      }
    }

    // Retrieve active scan assessment for popup
    if (message.action === 'GET_SCAN_DATA') {
      const tabId = message.tabId || senderTabId;
      if (!tabId) {
        sendResponse({ success: false, error: 'No tab id provided' });
        return false;
      }

      const cached = tabCache.get(tabId);
      if (cached) {
        sendResponse({ success: true, assessment: cached });
        return false;
      }

      getStorage(`tab_${tabId}`).then((stored) => {
        if (stored) {
          tabCache.set(tabId, stored);
          sendResponse({ success: true, assessment: stored });
        } else {
          chrome.tabs.get(tabId).then((tab) => {
            if (tab && tab.url) {
              analyzeTab(tabId, tab.url).then((fresh) => {
                sendResponse({ success: true, assessment: fresh });
              });
            } else {
              sendResponse({ success: false, error: 'Tab is inaccessible' });
            }
          }).catch((err) => sendResponse({ success: false, error: err.message }));
        }
      });
      return true;
    }

    // Force re-scan of a tab
    if (message.action === 'RESCAN_TAB') {
      const tabId = message.tabId;
      chrome.tabs.get(tabId).then((tab) => {
        if (tab && tab.url) {
          lastAnalyzedUrlByTab.delete(tabId); // invalidate cache
          analyzeTab(tabId, tab.url).then((assessment) => {
            sendResponse({ success: true, assessment });
          });
        } else {
          sendResponse({ success: false, error: 'Tab not found' });
        }
      }).catch(err => sendResponse({ success: false, error: err.message }));
      return true;
    }

    // Scan history query
    if (message.action === 'GET_SCAN_HISTORY') {
      getStorage('sentinel_scan_history', [])
        .then(history => sendResponse({ success: true, history }))
        .catch(err => sendResponse({ success: false, error: err.message }));
      return true;
    }

    // Toggle Whitelist
    if (message.action === 'TOGGLE_WHITELIST') {
      const { hostname, whitelist, tabId } = message;
      getStorage('sentinel_whitelist', []).then(async (list) => {
        let updated = [...list];
        if (whitelist) {
          if (!updated.includes(hostname)) updated.push(hostname);
        } else {
          updated = updated.filter(h => h !== hostname);
        }
        await setStorage('sentinel_whitelist', updated);
        if (tabId) {
          chrome.tabs.get(tabId).then((tab) => {
            if (tab && tab.url) {
              lastAnalyzedUrlByTab.delete(tabId);
              analyzeTab(tabId, tab.url);
            }
          });
        }
        sendResponse({ success: true, whitelist: updated });
      });
      return true;
    }

    // Token Status Query
    if (message.action === 'GET_TOKEN_STATUS') {
      (async () => {
        const user = await getStorage('sentinel_user', null);
        const guestScans = await getStorage('sentinel_guest_scans', 0);
        const demoScans = await getStorage('sentinel_demo_scans', 0);
        let status = {
          tier: user ? (user.account_tier || (user.email === 'demo@sentinelai.security' ? 'demo' : 'personal')) : 'guest',
          user: user || null,
          guestScans,
          demoScans,
          limit: !user ? 1 : (user.email === 'demo@sentinelai.security' || user.account_tier === 'demo') ? 5 : (user.scan_tokens || 50),
          remaining: !user ? Math.max(0, 1 - guestScans) : (user.email === 'demo@sentinelai.security' || user.account_tier === 'demo') ? Math.max(0, 5 - demoScans) : 50
        };
        sendResponse({ success: true, status });
      })();
      return true;
    }

    // Sync User Session into Extension Storage
    if (message.action === 'SYNC_USER_SESSION') {
      (async () => {
        if (message.user) {
          await setStorage('sentinel_user', message.user);
          if (message.token) await setStorage('sentinel_token', message.token);
        } else {
          await chrome.storage.local.remove(['sentinel_user', 'sentinel_token']);
        }
        sendResponse({ success: true });
      })();
      return true;
    }

    // Open Dashboard Page
    if (message.action === 'OPEN_DASHBOARD') {
      const view = message.view || 'overview';
      const dashboardUrl = chrome.runtime.getURL(`dashboard/index.html#${view}`);
      chrome.tabs.create({ url: dashboardUrl }, () => {
        sendResponse({ success: true });
      });
      return true;
    }

    return false;
  });
}

// Module exports for Node.js unit testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    investigateUrl,
    extractUrlFeatures,
    analyzeTab,
    isInternalUrl,
    updateBadge,
    isWhitelisted,
    getStorage,
    setStorage,
    syncLocalDashboard,
    ACTIVE_MODEL_VERSION
  };
}
