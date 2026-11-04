/**
 * SentinelAI: Phishing & Scam Link Shield
 * Local Machine Learning & Heuristic Inference Engine
 *
 * Evaluates extracted URL metrics on-device with zero telemetry or network calls.
 * Transpiled decision ensemble and logistic scoring returning a probability float [0.0, 1.0].
 */

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
 * Predicts the phishing and scam probability score for a given set of URL features.
 *
 * @param {number[] | object} features - Feature vector or feature object:
 *   [0]  urlLength                Total character count of URL
 *   [1]  domainLength             Hostname character count
 *   [2]  isIp                     1 if hostname is a raw IPv4/IPv6 address, else 0
 *   [3]  numDots                  Number of dots in hostname
 *   [4]  numHyphens               Number of hyphens in hostname (typosquatting)
 *   [5]  hasAtSymbol              1 if '@' present in URL (credential masking)
 *   [6]  numSubdomains            Depth of subdomains beyond root
 *   [7]  isHttps                  1 if HTTPS protocol, 0 if HTTP
 *   [8]  hasSuspiciousTld         1 if TLD is high-abuse (.xyz, .top, .tk, etc.)
 *   [9]  suspiciousKeywordsCount  Count of auth/banking keywords in URL
 *   [10] specialCharCount         Count of %&=?_~ in URL
 *   [11] domainEntropy            Shannon entropy of hostname (DGA detection)
 *   [12] hasDoubleSlashInPath     1 if '//' appears in URL path
 *
 * @returns {number} Scam probability between 0.0 (safe) and 1.0 (critical phishing).
 */
function predictPhishingScore(features) {
  // Normalize features whether passed as an Array or Object
  let f = [];
  if (Array.isArray(features)) {
    f = features.map(v => (typeof v === 'number' && !isNaN(v) ? v : 0));
    while (f.length < 13) f.push(0);
  } else if (features && typeof features === 'object') {
    f = [
      Number(features.urlLength || 0),
      Number(features.domainLength || 0),
      Number(features.isIp ? 1 : 0),
      Number(features.numDots || 0),
      Number(features.numHyphens || 0),
      Number(features.hasAtSymbol ? 1 : 0),
      Number(features.numSubdomains || 0),
      Number(features.isHttps !== undefined ? (features.isHttps ? 1 : 0) : 1),
      Number(features.hasSuspiciousTld ? 1 : 0),
      Number(features.suspiciousKeywordsCount || 0),
      Number(features.specialCharCount || 0),
      Number(features.domainEntropy || 0),
      Number(features.hasDoubleSlashInPath ? 1 : 0)
    ];
  } else {
    return 0.5; // Neutral fallback on invalid input
  }

  const urlLength = f[0];
  const domainLength = f[1];
  const isIp = f[2];
  const numDots = f[3];
  const numHyphens = f[4];
  const hasAtSymbol = f[5];
  const numSubdomains = f[6];
  const isHttps = f[7];
  const hasSuspiciousTld = f[8];
  const keywords = f[9];
  const specialChars = f[10];
  const entropy = f[11];
  const hasDoubleSlash = f[12];

  // --- Decision Ensemble: 8 Transpiled Estimator Trees ---

  // Tree 1: Raw IP & Masking Characters (Critical bypass indicators)
  let t1 = 0.05;
  if (isIp >= 1.0) {
    t1 = 0.99;
  } else if (hasAtSymbol >= 1.0) {
    t1 = 0.98;
  } else if (isHttps === 0 && keywords >= 1.0) {
    t1 = 0.95;
  } else if (domainLength > 28.0 && entropy > 3.5) {
    t1 = 0.85;
  }

  // Tree 2: Suspicious TLD & Authentication Keyword Clusters
  let t2 = 0.04;
  if (isIp >= 1.0 || hasAtSymbol >= 1.0) {
    t2 = 0.99;
  } else if (hasSuspiciousTld >= 1.0) {
    if (keywords >= 1.0 || numSubdomains >= 1.0 || numHyphens >= 1.0) {
      t2 = 0.97;
    } else {
      t2 = 0.82;
    }
  } else if (keywords >= 2.0) {
    t2 = 0.92;
  } else if (keywords === 1.0 && urlLength > 75.0) {
    t2 = 0.65;
  }

  // Tree 3: Domain Entropy & Algorithmic Generation (DGA detection)
  let t3 = 0.04;
  if (isIp >= 1.0) {
    t3 = 0.99;
  } else if (entropy >= 3.65) {
    if (domainLength > 16.0 || keywords >= 1.0) {
      t3 = 0.96;
    } else {
      t3 = 0.78;
    }
  } else if (hasSuspiciousTld >= 1.0 && keywords >= 1.0) {
    t3 = 0.95;
  } else if (numDots >= 3.0 && keywords >= 1.0) {
    t3 = 0.84;
  }

  // Tree 4: Subdomains, Typosquatting & Hyphenation
  let t4 = 0.05;
  if (isIp >= 1.0 || hasAtSymbol >= 1.0) {
    t4 = 0.98;
  } else if (numSubdomains >= 2.0) {
    if (keywords >= 1.0 || hasSuspiciousTld >= 1.0) {
      t4 = 0.96;
    } else {
      t4 = 0.75;
    }
  } else if (numHyphens >= 2.0) {
    if (keywords >= 1.0 || hasSuspiciousTld >= 1.0) {
      t4 = 0.94;
    } else {
      t4 = 0.70;
    }
  }

  // Tree 5: Protocol Security & Special Characters Evasion
  let t5 = 0.05;
  if (isIp >= 1.0) {
    t5 = 0.99;
  } else if (isHttps === 0) {
    if (keywords >= 1.0 || hasSuspiciousTld >= 1.0) {
      t5 = 0.98;
    } else {
      t5 = 0.75;
    }
  } else if (hasDoubleSlash >= 1.0) {
    t5 = 0.92;
  } else if (specialChars >= 6.0 && keywords >= 1.0) {
    t5 = 0.88;
  }

  // Tree 6: Keyword Weighting & Sensitive Action Patterns
  let t6 = 0.04;
  if (isIp >= 1.0 || hasAtSymbol >= 1.0) {
    t6 = 0.99;
  } else if (keywords >= 2.0) {
    t6 = 0.98;
  } else if (keywords === 1.0) {
    if (hasSuspiciousTld >= 1.0 || isHttps === 0 || numSubdomains >= 2.0) {
      t6 = 0.95;
    } else if (urlLength > 65.0) {
      t6 = 0.55;
    } else {
      t6 = 0.20;
    }
  }

  // Tree 7: Deep Structural Redirection & URL Length
  let t7 = 0.04;
  if (isIp >= 1.0 || hasAtSymbol >= 1.0) {
    t7 = 0.99;
  } else if (hasDoubleSlash >= 1.0) {
    t7 = 0.94;
  } else if (urlLength > 100.0 && (keywords >= 1.0 || hasSuspiciousTld >= 1.0)) {
    t7 = 0.91;
  } else if (domainLength > 30.0 && numDots >= 2.0) {
    t7 = 0.76;
  }

  // Tree 8: Complex Multi-Vector Correlation
  let t8 = 0.05;
  if (isIp >= 1.0) {
    t8 = 0.99;
  } else if (hasSuspiciousTld >= 1.0 && (isHttps === 0 || keywords >= 1.0)) {
    t8 = 0.98;
  } else if (numSubdomains >= 2.0 && numHyphens >= 1.0) {
    t8 = 0.86;
  } else if (entropy > 3.4 && keywords >= 1.0) {
    t8 = 0.89;
  }

  // Compute ensemble mean across the 8 trees
  const ensembleMean = (t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8) / 8.0;

  // Direct threat overrides for deterministic, undeniable phishing vectors
  let finalScore = ensembleMean;
  if (isIp >= 1.0) {
    finalScore = Math.max(finalScore, 0.96);
  }
  if (hasAtSymbol >= 1.0) {
    finalScore = Math.max(finalScore, 0.95);
  }
  if (hasSuspiciousTld >= 1.0 && keywords >= 1.0) {
    finalScore = Math.max(finalScore, 0.94);
  }
  if (isHttps === 0 && keywords >= 1.0 && numSubdomains >= 1.0) {
    finalScore = Math.max(finalScore, 0.92);
  }

  return Number(Math.max(0.0, Math.min(1.0, finalScore)).toFixed(3));
}

// Global exposure for service workers (importScripts) and browser contexts
if (typeof self !== 'undefined') {
  self.predictPhishingScore = predictPhishingScore;
  self.calculateEntropy = calculateEntropy;
}
if (typeof window !== 'undefined') {
  window.predictPhishingScore = predictPhishingScore;
  window.calculateEntropy = calculateEntropy;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    predictPhishingScore,
    calculateEntropy
  };
}
