/**
 * SentinelAI Phishing & Scam Link Shield
 * Canonical JavaScript Feature Extractor
 *
 * Implements the exact 14-dimensional feature vector matching ml/canonical_schema.json
 * and ml/features.py with verified parity across all features.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js CommonJS
    module.exports = factory();
  } else {
    // Browser / Service Worker global
    root.SentinelFeatures = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FEATURE_NAMES = [
    'url_length',
    'domain_length',
    'num_dots',
    'has_ip',
    'has_at_symbol',
    'num_hyphens',
    'num_subdomains',
    'is_https',
    'has_double_slash_in_path',
    'num_suspicious_keywords',
    'has_suspicious_tld',
    'num_query_params',
    'special_char_count',
    'domain_entropy'
  ];

  const SUSPICIOUS_TLDS = new Set([
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz',
    'fit', 'work', 'icu', 'loan', 'click', 'country', 'kim',
    'science', 'monster', 'quest', 'live', 'cam', 'rest',
    'gdn', 'stream', 'party', 'trade', 'bid', 'men', 'surf',
    'zip', 'mov'
  ]);

  const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'update',
    'banking', 'secure', 'account', 'confirm', 'password',
    'credential', 'auth', 'recover', 'wallet', 'security',
    'billing', 'invoice', 'appleid', 'paypal', 'metamask'
  ];

  const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const IPV6_REGEX = /^\[?[a-fA-F0-9:]+\]?$/;

  /**
   * Calculates Shannon Entropy of a string to detect algorithmic/DGA domain names.
   * @param {string} text
   * @returns {number} Float rounded to 3 decimal places.
   */
  function calculateEntropy(text) {
    if (!text || text.length === 0) return 0.0;
    const counts = {};
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      counts[c] = (counts[c] || 0) + 1;
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
   * Checks if a hostname is an IPv4 or IPv6 address.
   * @param {string} hostname
   * @returns {number} 1 if IP, 0 otherwise.
   */
  function checkIsIp(hostname) {
    if (!hostname) return 0;
    const clean = hostname.replace(/^\[|\]$/g, '');
    if (IPV4_REGEX.test(clean)) return 1;
    if (clean.includes(':') && IPV6_REGEX.test(clean)) return 1;
    return 0;
  }

  /**
   * Parses a raw URL string into standard components.
   */
  function parseUrl(rawUrl) {
    let clean = (rawUrl || '').trim();
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(clean)) {
      clean = 'http://' + clean;
    }
    try {
      const parsed = new URL(clean);
      return {
        scheme: parsed.protocol.replace(':', '').toLowerCase(),
        hostname: (parsed.hostname || '').replace(/^\[|\]$/g, '').toLowerCase(),
        pathname: parsed.pathname || '',
        search: parsed.search || '',
        fullUrl: clean.toLowerCase()
      };
    } catch (e) {
      // Fallback regex parsing if new URL fails
      const match = clean.match(/^([a-zA-Z0-9+.-]+):\/\/([^/?#]+)([^?#]*)(\?[^#]*)?/);
      return {
        scheme: match ? match[1].toLowerCase() : 'http',
        hostname: match ? match[2].split(':')[0].toLowerCase() : '',
        pathname: match && match[3] ? match[3] : '',
        search: match && match[4] ? match[4] : '',
        fullUrl: clean.toLowerCase()
      };
    }
  }

  /**
   * Extracts the canonical 14 features matching Python features.py.
   * @param {string} rawUrl
   * @returns {number[]} 14-element feature vector.
   */
  function extractFeatures(rawUrl) {
    const { scheme, hostname, pathname, search, fullUrl } = parseUrl(rawUrl);

    // [0] url_length
    const urlLength = fullUrl.length;

    // [1] domain_length
    const domainLength = hostname.length;

    // [2] num_dots
    const numDots = (hostname.match(/\./g) || []).length;

    // [3] has_ip
    const hasIp = checkIsIp(hostname);

    // [4] has_at_symbol
    const hasAtSymbol = fullUrl.includes('@') ? 1 : 0;

    // [5] num_hyphens
    const numHyphens = (hostname.match(/-/g) || []).length;

    // [6] num_subdomains
    const parts = hostname.split('.').filter(Boolean);
    let numSubdomains = 0;
    if (hasIp === 1) {
      numSubdomains = 0;
    } else if (parts.length > 2) {
      numSubdomains = parts.length - 2;
    }

    // [7] is_https
    const isHttps = scheme === 'https' ? 1 : 0;

    // [8] has_double_slash_in_path
    const hasDoubleSlashInPath = pathname.includes('//') ? 1 : 0;

    // [9] num_suspicious_keywords
    const query = search.startsWith('?') ? search.slice(1) : search;
    const targetString = (pathname + '?' + query).toLowerCase();
    let numSuspiciousKeywords = 0;
    for (let i = 0; i < SUSPICIOUS_KEYWORDS.length; i++) {
      if (targetString.includes(SUSPICIOUS_KEYWORDS[i])) {
        numSuspiciousKeywords++;
      }
    }

    // [10] has_suspicious_tld
    const tld = parts.length > 0 ? parts[parts.length - 1] : '';
    const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;

    // [11] num_query_params
    let numQueryParams = 0;
    if (query.length > 0) {
      const qp = query.split('&').filter(Boolean);
      numQueryParams = qp.length;
    }

    // [12] special_char_count (%&=?_~)
    const specialCharCount = (fullUrl.match(/[%&=?_~]/g) || []).length;

    // [13] domain_entropy
    const domainEntropy = calculateEntropy(hostname);

    return [
      urlLength,
      domainLength,
      numDots,
      hasIp,
      hasAtSymbol,
      numHyphens,
      numSubdomains,
      isHttps,
      hasDoubleSlashInPath,
      numSuspiciousKeywords,
      hasSuspiciousTld,
      numQueryParams,
      specialCharCount,
      domainEntropy
    ];
  }

  /**
   * Returns features mapped as key-value pairs.
   * @param {string} rawUrl
   * @returns {Object}
   */
  function extractFeaturesDict(rawUrl) {
    const arr = extractFeatures(rawUrl);
    const obj = {};
    for (let i = 0; i < FEATURE_NAMES.length; i++) {
      obj[FEATURE_NAMES[i]] = arr[i];
    }
    return obj;
  }

  return {
    FEATURE_NAMES,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
    calculateEntropy,
    checkIsIp,
    extractFeatures,
    extractFeaturesDict
  };
});
