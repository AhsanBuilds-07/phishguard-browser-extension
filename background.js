/**
 * SentinelAI: Phishing & Scam Link Shield
 * Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 * 1. Imports the generated scikit-learn inference model via importScripts.
 * 2. Listens to chrome.webNavigation.onCompleted and chrome.tabs updates.
 * 3. Extracts live lexical and structural URL features (IP presence, length, keywords, entropy).
 * 4. Runs local ML prediction via predictPhishingScore(features).
 * 5. Updates extension badge text and colors (SAFE: Green, WARN: Amber, RISK: Red).
 * 6. Persists scan assessments to chrome.storage.local for popup dashboard access.
 * 7. Programmatically injects content.js if risk score > 0.75.
 */

// Load the generated RandomForest model trained from the labeled URL dataset.
if (typeof importScripts === 'function') {
  importScripts('ml/features.js', 'ml/models/model_exported.js');
}

const featureAPI = typeof SentinelFeatures !== 'undefined'
  ? SentinelFeatures
  : (typeof require === 'function' ? require('./ml/features.js') : null);
const MAX_SCAN_HISTORY = 100;
const modelAPI = typeof SentinelModel !== 'undefined'
  ? SentinelModel
  : (typeof require === 'function' ? require('./ml/models/model_exported.js') : null);
const ACTIVE_MODEL_VERSION = modelAPI?.MODEL_VERSION || 'rf-20261104-183213';

// In-memory cache for ultra-fast tab lookup
const tabCache = new Map();

// ============================================================================
// Storage Utilities
// ============================================================================

/**
 * Reads data from chrome.storage.local with a default fallback.
 */
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

/**
 * Saves a key-value pair to chrome.storage.local.
 */
function setStorage(key, value) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [key]: value }, () => resolve());
  });
}

/**
 * Checks if a hostname is on the user's whitelist.
 */
async function isWhitelisted(hostname) {
  if (!hostname) return false;
  const list = await getStorage('sentinel_whitelist', []);
  const clean = hostname.toLowerCase();
  return list.some(d => clean === d || clean.endsWith('.' + d));
}

// ============================================================================
// URL Feature Extraction
// ============================================================================

/**
 * Calculates Shannon Entropy of a string to detect algorithmic/DGA domain names.
 * @param {string} text
 * @returns {number}
 */
function calculateEntropy(text) {
  if (!text || text.length === 0) return 0.0;
  const counts = {};
  for (const char of text) {
    counts[char] = (counts[char] || 0) + 1;
  }

  let entropy = 0.0;
  const len = text.length;
  for (const char in counts) {
    const p = counts[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Determines whether a URL is internal browser navigation.
 */
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

/**
 * Extracts the canonical 14-feature vector matching ml/features.py and ml/features.js.
 *
 * @param {string} rawUrl
 * @returns {{ features: object, featureArray: number[], breakdown: object, flags: string[] }}
 */
function extractUrlFeatures(rawUrl) {
  try {
    let cleanUrl = (rawUrl || '').trim();
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(cleanUrl)) {
      cleanUrl = `http://${cleanUrl}`;
    }

    const parsed = new URL(cleanUrl);
    const hostname = (parsed.hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
    const pathname = (parsed.pathname || '').toLowerCase();
    const query = (parsed.search || '').toLowerCase().replace(/^\?/, '');
    const featureArray = featureAPI.extractFeatures(cleanUrl);
    const featureValues = Object.fromEntries(
      featureAPI.FEATURE_NAMES.map((name, index) => [name, featureArray[index]])
    );
    const parts = hostname.split('.').filter(Boolean);
    const tld = parts.length > 0 ? parts[parts.length - 1] : '';
    const matchedKeywords = featureAPI.SUSPICIOUS_KEYWORDS.filter(keyword =>
      `${pathname}?${query}`.includes(keyword)
    );
    const urlLength = featureValues.url_length;
    const domainLength = featureValues.domain_length;
    const numDots = featureValues.num_dots;
    const hasIp = featureValues.has_ip;
    const hasAtSymbol = featureValues.has_at_symbol;
    const numHyphens = featureValues.num_hyphens;
    const numSubdomains = featureValues.num_subdomains;
    const isHttps = featureValues.is_https;
    const hasDoubleSlashInPath = featureValues.has_double_slash_in_path;
    const suspiciousKeywordsCount = featureValues.num_suspicious_keywords;
    const hasSuspiciousTld = featureValues.has_suspicious_tld;
    const numQueryParams = featureValues.num_query_params;
    const specialChars = featureValues.special_char_count;
    const domainEntropy = featureValues.domain_entropy;

    const flags = [];
    if (hasIp === 1) flags.push('Raw IP address used instead of legitimate domain name');
    if (hasAtSymbol === 1) flags.push('Contains "@" credential-masking delimiter in URL');
    if (isHttps === 0) flags.push('Unencrypted connection (insecure HTTP scheme)');
    if (hasSuspiciousTld === 1) flags.push(`High-abuse Top-Level Domain (.${tld}) commonly used in phishing`);
    if (matchedKeywords.length > 0) flags.push(`Sensitive credential/banking keywords detected: ${matchedKeywords.join(', ')}`);
    if (numSubdomains >= 2) flags.push(`Excessive subdomain depth (${numSubdomains} levels)`);
    if (numHyphens >= 2) flags.push(`Excessive hyphens in hostname (${numHyphens}) - typosquatting signal`);
    if (domainEntropy > 3.5) flags.push(`High algorithmic domain randomness (Shannon entropy: ${domainEntropy})`);
    if (hasDoubleSlashInPath === 1) flags.push('Open redirection path evasion pattern (//) detected');

    const featureObj = {
      urlLength,
      domainLength,
      numDots,
      hasIp,
      hasAtSymbol,
      numHyphens,
      numSubdomains,
      isHttps,
      hasDoubleSlashInPath,
      suspiciousKeywordsCount,
      hasSuspiciousTld,
      numQueryParams,
      specialCharCount: specialChars,
      domainEntropy
    };

    const breakdown = {
      hostname,
      protocol: parsed.protocol,
      urlLength,
      domainLength,
      numDots,
      hasIp: Boolean(hasIp),
      hasAtSymbol: Boolean(hasAtSymbol),
      numHyphens,
      numSubdomains,
      isHttps: Boolean(isHttps),
      hasDoubleSlashInPath: Boolean(hasDoubleSlashInPath),
      matchedKeywords,
      tld,
      hasSuspiciousTld: Boolean(hasSuspiciousTld),
      numQueryParams,
      specialChars,
      domainEntropy
    };

    return { features: featureObj, featureArray, breakdown, flags };
  } catch (err) {
    return {
      features: {},
      featureArray: new Array(14).fill(0),
      breakdown: { hostname: 'Invalid URL', protocol: '' },
      flags: ['Invalid or unparseable URL']
    };
  }
}

/**
 * Produces an explainable investigation using the deployed trained model.
 * Network reputation and certificate validation are deliberately not inferred
 * from URL-only evidence.
 */
function investigateUrl(rawUrl) {
  if (!modelAPI) {
    throw new Error('The trained phishing model is unavailable.');
  }
  const { features, featureArray, breakdown, flags } = extractUrlFeatures(rawUrl);
  if (featureArray.length !== 14 || !breakdown.hostname || breakdown.hostname === 'Invalid URL') {
    throw new Error('Enter a valid HTTP or HTTPS URL to investigate.');
  }

  const probabilities = modelAPI.predictProba(featureArray);
  const riskScore = Number(probabilities[1].toFixed(4));
  const riskLevel = riskScore > 0.75 ? 'RISK' : riskScore >= 0.40 ? 'WARN' : 'SAFE';
  const evidence = [...flags];
  if (riskScore >= 0.40 && evidence.length === 0) {
    evidence.push('The trained model identified a suspicious combination of URL structure features.');
  }

  return {
    url: rawUrl.trim(),
    hostname: breakdown.hostname,
    riskScore,
    riskLevel,
    statusText: riskLevel === 'RISK'
      ? 'The trained model estimates a high phishing probability. Avoid entering credentials.'
      : riskLevel === 'WARN'
        ? 'The trained model found signals that warrant caution.'
        : 'The trained model found a low phishing probability from the available URL features.',
    modelVersion: ACTIVE_MODEL_VERSION,
    modelType: 'RandomForestClassifier',
    probabilities: { benign: probabilities[0], phishing: probabilities[1] },
    featureSchema: modelAPI.FEATURE_NAMES,
    features,
    breakdown,
    evidence,
    limitations: [
      'This report evaluates URL structure only; it does not query live threat-intelligence feeds.',
      'HTTPS indicates the URL scheme, not that a certificate was validated here.'
    ],
    timestamp: Date.now()
  };
}

async function saveScanHistory(report) {
  if (typeof chrome === 'undefined') return;
  const history = await getStorage('sentinel_scan_history', []);
  const next = [report, ...history.filter(item => item.url !== report.url)].slice(0, MAX_SCAN_HISTORY);
  await setStorage('sentinel_scan_history', next);
}

async function syncLocalDashboard(report) {
  const enabled = await getStorage('sentinel_local_dashboard_sync', false);
  if (enabled !== true) return;

  try {
    const response = await fetch('http://127.0.0.1:8000/api/extension-events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: report.url })
    });
    if (!response.ok) {
      console.warn(`[SentinelAI] Local dashboard sync failed with HTTP ${response.status}.`);
    }
  } catch (error) {
    console.warn('[SentinelAI] Local dashboard is unavailable for opted-in scan sync.', error);
  }
}

// ============================================================================
// Badge Visualizer
// ============================================================================

/**
 * Updates extension action badge text and background color according to threat status.
 *
 * @param {number} tabId
 * @param {'SAFE' | 'WARN' | 'RISK' | 'INTERNAL' | 'WHITELISTED'} status
 */
function updateBadge(tabId, status) {
  if (status === 'INTERNAL') {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }
  if (status === 'WHITELISTED') {
    chrome.action.setBadgeText({ tabId, text: 'SAFE' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' }); // Green
    return;
  }
  if (status === 'RISK') {
    chrome.action.setBadgeText({ tabId, text: 'RISK' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#EF4444' }); // Red
    return;
  }
  if (status === 'WARN') {
    chrome.action.setBadgeText({ tabId, text: 'WARN' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#F59E0B' }); // Amber
    return;
  }
  // Default SAFE
  chrome.action.setBadgeText({ tabId, text: 'SAFE' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' }); // Green
}

// ============================================================================
// Core Analysis Pipeline
// ============================================================================

/**
 * Evaluates the safety of a tab's URL using the on-device AI model.
 *
 * @param {number} tabId
 * @param {string} url
 */
async function analyzeTab(tabId, url) {
  if (!url || isInternalUrl(url)) {
    const internalReport = {
      tabId,
      url: url || 'Browser Page',
      hostname: 'System Page',
      riskScore: 0.0,
      riskLevel: 'INTERNAL',
      statusText: 'Internal browser page. Isolated from network threats.',
      flags: [],
      timestamp: Date.now()
    };
    tabCache.set(tabId, internalReport);
    updateBadge(tabId, 'INTERNAL');
    await setStorage(`tab_${tabId}`, internalReport);
    return internalReport;
  }

  // Extract features
  const report = investigateUrl(url);
  const { features, breakdown, evidence: flags } = report;
  const hostname = breakdown.hostname || '';

  // Check user whitelist
  const whitelisted = await isWhitelisted(hostname);
  if (whitelisted) {
    const whiteReport = {
      tabId,
      url,
      hostname,
      riskScore: 0.0,
      riskLevel: 'WHITELISTED',
      statusText: 'Trusted Domain. Added to personal whitelist.',
      flags: ['Domain explicitly trusted by user'],
      whitelisted: true,
      breakdown,
      modelVersion: ACTIVE_MODEL_VERSION,
      timestamp: Date.now()
    };
    tabCache.set(tabId, whiteReport);
    updateBadge(tabId, 'WHITELISTED');
    await setStorage(`tab_${tabId}`, whiteReport);
    await setStorage('last_scan_result', whiteReport);
    await setStorage('last_scanned_url', url);
    return whiteReport;
  }

  // Run on-device local AI inference
  const riskScore = report.riskScore;

  let riskLevel = 'SAFE';
  let statusText = 'Low Risk: URL structure appears legitimate.';

  if (riskScore > 0.75) {
    riskLevel = 'RISK';
    statusText = 'Critical Risk: High probability of phishing or scam link!';
  } else if (riskScore >= 0.40) {
    riskLevel = 'WARN';
    statusText = 'Caution: Suspicious URL characteristics detected.';
  }

  const assessment = {
    tabId,
    url,
    hostname,
    riskScore,
    riskLevel,
    statusText,
    modelVersion: report.modelVersion,
    modelType: report.modelType,
    probabilities: report.probabilities,
    whitelisted: false,
    flags,
    breakdown,
    timestamp: Date.now()
  };

  tabCache.set(tabId, assessment);
  updateBadge(tabId, riskLevel);

  // Persist assessment in chrome.storage.local for popup dashboard
  await setStorage(`tab_${tabId}`, assessment);
  await setStorage('last_scan_result', assessment);
  await setStorage('last_scanned_url', url);
  await saveScanHistory(assessment);
  void syncLocalDashboard(assessment);

  // If risk score > 0.75, inject content.js and dispatch warning
  if (riskScore > 0.75) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ['content.js']
      });
    } catch (e) {
      // Script may already be injected or page navigation in progress
    }

    // Send threat alert message to content script
    chrome.tabs.sendMessage(tabId, {
      action: 'TRIGGER_WARNING_OVERLAY',
      report: assessment
    }).catch(() => {});
  }

  return assessment;
}

// ============================================================================
// Event Listeners
// ============================================================================

if (typeof chrome !== 'undefined') {
  // 1. chrome.webNavigation.onCompleted listener (Main Navigation Target)
  chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId === 0 && details.url) {
      analyzeTab(details.tabId, details.url);
    }
  });

  // 2. Fallback tab updates (e.g., dynamic client-side SPA routing)
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url || (changeInfo.status === 'complete' && tab.url)) {
      const targetUrl = changeInfo.url || tab.url;
      if (targetUrl) {
        analyzeTab(tabId, targetUrl);
      }
    }
  });

  // 3. Tab switch: synchronizes badge and active scan report
  chrome.tabs.onActivated.addListener(async (activeInfo) => {
    const cached = tabCache.get(activeInfo.tabId);
    if (cached) {
      updateBadge(activeInfo.tabId, cached.riskLevel);
      await setStorage('last_scan_result', cached);
      await setStorage('last_scanned_url', cached.url);
    } else {
      try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (tab && tab.url) {
          analyzeTab(activeInfo.tabId, tab.url);
        }
      } catch (e) {}
    }
  });

  // 4. Tab cleanup
  chrome.tabs.onRemoved.addListener((tabId) => {
    tabCache.delete(tabId);
    chrome.storage.local.remove([`tab_${tabId}`], () => {});
  });

  // ============================================================================
  // Message Passing Handler (Popup & Content Script Communication)
  // ============================================================================

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const senderTabId = sender?.tab?.id;

    if (message.action === 'INVESTIGATE_URL') {
      try {
        const report = investigateUrl(message.url || '');
        saveScanHistory(report).then(() => sendResponse({ success: true, report }));
      } catch (error) {
        sendResponse({ success: false, error: error.message });
      }
      return true;
    }

    if (message.action === 'GET_SCAN_HISTORY') {
      getStorage('sentinel_scan_history', [])
        .then(history => sendResponse({ success: true, history }))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true;
    }

    // Retrieve scan data for popup
    if (message.action === 'GET_SCAN_DATA') {
      const tabId = message.tabId || senderTabId;
      if (!tabId) {
        sendResponse({ success: false, error: 'No tab id' });
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
              sendResponse({ success: false, error: 'Tab inaccessible' });
            }
          }).catch((err) => sendResponse({ success: false, error: err.message }));
        }
      });

      return true; // Keep channel open for async response
    }

    // Force re-scan of a tab
    if (message.action === 'RESCAN_TAB') {
      const tabId = message.tabId;
      chrome.tabs.get(tabId).then((tab) => {
        if (tab && tab.url) {
          analyzeTab(tabId, tab.url).then((assessment) => {
            sendResponse({ success: true, assessment });
          });
        } else {
          sendResponse({ success: false, error: 'Tab not found' });
        }
      }).catch(err => sendResponse({ success: false, error: err.message }));
      return true;
    }

    // Whitelist toggle
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
            if (tab && tab.url) analyzeTab(tabId, tab.url);
          });
        }
        sendResponse({ success: true, whitelist: updated });
      });
      return true;
    }

    return false;
  });
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    analyzeTab,
    extractUrlFeatures,
    investigateUrl,
    syncLocalDashboard,
    ACTIVE_MODEL_VERSION,
    isInternalUrl,
    getStorage,
    setStorage,
    isWhitelisted,
    updateBadge,
    calculateEntropy
  };
}
