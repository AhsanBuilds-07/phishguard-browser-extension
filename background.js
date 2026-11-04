/**
 * SentinelAI: Phishing & Scam Link Shield
 * Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 * 1. Imports local inference model via importScripts('model.js').
 * 2. Listens to chrome.webNavigation.onCompleted and chrome.tabs updates.
 * 3. Extracts live lexical and structural URL features (IP presence, length, keywords, entropy).
 * 4. Runs local ML prediction via predictPhishingScore(features).
 * 5. Updates extension badge text and colors (SAFE: Green, WARN: Amber, RISK: Red).
 * 6. Persists scan assessments to chrome.storage.local for popup dashboard access.
 * 7. Programmatically injects content.js if risk score > 0.75.
 */

// Load the local machine learning inference model
importScripts('model.js');

// High-abuse Top-Level Domains frequently registered for scam campaigns
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz',
  'fit', 'work', 'icu', 'loan', 'click', 'country', 'kim',
  'science', 'monster', 'quest', 'live', 'cam', 'rest',
  'gdn', 'stream', 'party', 'trade', 'bid', 'men', 'surf',
  'zip', 'mov'
]);

// Authentication, credential harvesting, and financial keywords
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'update',
  'banking', 'secure', 'account', 'confirm', 'confirmation', 'password',
  'credential', 'auth', 'recover', 'wallet', 'ebayisapi',
  'webscr', 'security', 'validation', 'support-help', 'billing',
  'invoice', 'appleid', 'paypal', 'metamask', 'seedphrase'
];

// IP address detection patterns (IPv4 and IPv6)
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^\[?[a-fA-F0-9:]+\]?$/;

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
 * Extracts 13 heuristic metrics and semantic breakdown flags from any URL.
 *
 * @param {string} rawUrl
 * @returns {{ features: object, featureArray: number[], breakdown: object, flags: string[] }}
 */
function extractUrlFeatures(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const search = parsed.search.toLowerCase();
    const full = rawUrl.toLowerCase();

    const urlLength = full.length;
    const domainLength = hostname.length;

    // Check IP host
    const isIp = IPV4_REGEX.test(hostname) || (hostname.includes(':') && IPV6_REGEX.test(hostname)) ? 1 : 0;

    // Dots & Hyphens
    const numDots = (hostname.match(/\./g) || []).length;
    const numHyphens = (hostname.match(/-/g) || []).length;

    // Credential delimiter (@)
    const hasAtSymbol = full.includes('@') ? 1 : 0;

    // Subdomains count
    const parts = hostname.split('.').filter(Boolean);
    const numSubdomains = parts.length > 2 ? Math.max(0, parts.length - 2) : 0;

    // Protocol
    const isHttps = parsed.protocol === 'https:' ? 1 : 0;

    // TLD
    const tld = parts.length > 0 ? parts[parts.length - 1] : '';
    const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;

    // Keywords
    const targetString = `${pathname}?${search}`;
    let suspiciousKeywordsCount = 0;
    const matchedKeywords = [];
    for (const kw of SUSPICIOUS_KEYWORDS) {
      if (targetString.includes(kw)) {
        suspiciousKeywordsCount++;
        matchedKeywords.push(kw);
      }
    }

    // Special characters
    const specialChars = (full.match(/[%&=?_~]/g) || []).length;

    // Shannon Entropy
    const domainEntropy = calculateEntropy(hostname);

    // Double slash in path redirect evasion
    const hasDoubleSlashInPath = pathname.includes('//') ? 1 : 0;

    // Human-readable threat explanation flags
    const flags = [];
    if (isIp === 1) {
      flags.push('Raw IP address used instead of legitimate domain name');
    }
    if (hasAtSymbol === 1) {
      flags.push('Contains "@" credential-masking delimiter in URL');
    }
    if (isHttps === 0) {
      flags.push('Unencrypted connection (insecure HTTP scheme)');
    }
    if (hasSuspiciousTld === 1) {
      flags.push(`High-abuse Top-Level Domain (.${tld}) commonly used in phishing`);
    }
    if (matchedKeywords.length > 0) {
      flags.push(`Sensitive credential/banking keywords detected: ${matchedKeywords.join(', ')}`);
    }
    if (numSubdomains >= 2) {
      flags.push(`Excessive subdomain depth (${numSubdomains} levels)`);
    }
    if (numHyphens >= 2) {
      flags.push(`Excessive hyphens in hostname (${numHyphens}) - typosquatting signal`);
    }
    if (domainEntropy > 3.5) {
      flags.push(`High algorithmic domain randomness (Shannon entropy: ${domainEntropy})`);
    }
    if (hasDoubleSlashInPath === 1) {
      flags.push('Open redirection path evasion pattern (//) detected');
    }

    const featureObj = {
      urlLength,
      domainLength,
      isIp,
      numDots,
      numHyphens,
      hasAtSymbol,
      numSubdomains,
      isHttps,
      hasSuspiciousTld,
      suspiciousKeywordsCount,
      specialCharCount: specialChars,
      domainEntropy,
      hasDoubleSlashInPath
    };

    const featureArray = [
      urlLength,
      domainLength,
      isIp,
      numDots,
      numHyphens,
      hasAtSymbol,
      numSubdomains,
      isHttps,
      hasSuspiciousTld,
      suspiciousKeywordsCount,
      specialChars,
      domainEntropy,
      hasDoubleSlashInPath
    ];

    const breakdown = {
      hostname,
      protocol: parsed.protocol,
      urlLength,
      domainLength,
      isIp: Boolean(isIp),
      numDots,
      numHyphens,
      hasAtSymbol: Boolean(hasAtSymbol),
      numSubdomains,
      isHttps: Boolean(isHttps),
      tld,
      hasSuspiciousTld: Boolean(hasSuspiciousTld),
      matchedKeywords,
      specialChars,
      domainEntropy,
      hasDoubleSlashInPath: Boolean(hasDoubleSlashInPath)
    };

    return { features: featureObj, featureArray, breakdown, flags };
  } catch (err) {
    return {
      features: {},
      featureArray: new Array(13).fill(0),
      breakdown: { hostname: 'Invalid URL', protocol: '' },
      flags: ['Invalid or unparseable URL']
    };
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
  const { features, featureArray, breakdown, flags } = extractUrlFeatures(url);
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
  const riskScore = predictPhishingScore(featureArray);

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
