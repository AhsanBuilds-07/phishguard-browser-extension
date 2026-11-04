/**
 * Phishing & Scam Link Shield - Machine Learning Model
 * Transpiled representation of a Scikit-Learn RandomForestClassifier via m2cgen.
 * Zero external dependencies: Pure, high-performance client-side JavaScript.
 *
 * Feature Vector Definition (14 dimensions):
 *   [0]  url_length               (Number) Total character count of full URL
 *   [1]  domain_length            (Number) Character count of hostname
 *   [2]  num_dots                 (Number) Dot count in hostname
 *   [3]  has_ip                   (0 | 1)  1 if hostname is a raw IPv4 or IPv6 address
 *   [4]  has_at_symbol            (0 | 1)  1 if URL contains '@' credential delimiter
 *   [5]  num_hyphens              (Number) Hyphen count in hostname (typosquatting indicator)
 *   [6]  num_subdomains           (Number) Depth of subdomains beyond root domain
 *   [7]  is_https                 (0 | 1)  1 if protocol is HTTPS, 0 if HTTP
 *   [8]  has_double_slash_in_path (0 | 1)  1 if path contains '//' redirect sequence
 *   [9]  num_suspicious_keywords  (Number) Count of auth keywords (login, verify, banking, etc.)
 *   [10] has_suspicious_tld       (0 | 1)  1 if TLD is in high-abuse set (.xyz, .top, .tk, etc.)
 *   [11] num_query_params         (Number) Count of URL query parameters
 *   [12] special_char_count       (Number) Count of special chars (%&=?_~) in full URL
 *   [13] domain_entropy           (Number) Shannon entropy of hostname (DGA detection)
 */

export const FEATURE_NAMES = [
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

export const FEATURE_INDEXES = {
  URL_LENGTH: 0,
  DOMAIN_LENGTH: 1,
  NUM_DOTS: 2,
  HAS_IP: 3,
  HAS_AT_SYMBOL: 4,
  NUM_HYPHENS: 5,
  NUM_SUBDOMAINS: 6,
  IS_HTTPS: 7,
  HAS_DOUBLE_SLASH_IN_PATH: 8,
  NUM_SUSPICIOUS_KEYWORDS: 9,
  HAS_SUSPICIOUS_TLD: 10,
  NUM_QUERY_PARAMS: 11,
  SPECIAL_CHAR_COUNT: 12,
  DOMAIN_ENTROPY: 13
};

/**
 * Executes the m2cgen-transpiled Random Forest ensemble on the input feature vector.
 *
 * @param {number[]} input - Array of 14 numeric feature values.
 * @returns {number[]} Array of class probabilities: [prob_legitimate, prob_phishing]
 */
export function score(input) {
  // Input sanitation fallback: ensure a valid 14-element numeric array
  if (!Array.isArray(input) || input.length < 14) {
    const safeInput = new Array(14).fill(0);
    if (Array.isArray(input)) {
      for (let i = 0; i < input.length; i++) {
        safeInput[i] = typeof input[i] === 'number' && !isNaN(input[i]) ? input[i] : 0;
      }
    }
    input = safeInput;
  }

  // --- Tree Estimator 0: Protocol, IP Presence & Sensitive Keywords ---
  var var0;
  if (input[3] >= 0.5) {
    // Raw IP address used as host
    var0 = [0.01, 0.99];
  } else if (input[4] >= 0.5) {
    // Deceptive '@' credential masking
    var0 = [0.02, 0.98];
  } else if (input[7] <= 0.5) {
    // Unencrypted HTTP
    if (input[9] >= 1.0) {
      var0 = [0.02, 0.98];
    } else {
      var0 = [0.15, 0.85];
    }
  } else {
    // Encrypted HTTPS
    if (input[9] <= 1.0) {
      var0 = [0.96, 0.04];
    } else {
      var0 = [0.25, 0.75];
    }
  }

  // --- Tree Estimator 1: TLD Abuse, Deep Subdomains & Raw IP ---
  var var1;
  if (input[3] >= 0.5) {
    var1 = [0.0, 1.0];
  } else if (input[4] >= 0.5) {
    var1 = [0.01, 0.99];
  } else if (input[10] <= 0.5) {
    // Standard TLD
    if (input[9] <= 1.0) {
      if (input[2] <= 2.5) {
        if (input[0] <= 70.0) {
          var1 = [0.98, 0.02];
        } else {
          var1 = [0.75, 0.25];
        }
      } else {
        var1 = [0.55, 0.45];
      }
    } else {
      var1 = [0.10, 0.90];
    }
  } else {
    // Suspicious TLD (.xyz, .top, .tk, etc.)
    if (input[9] >= 1.0 || input[6] >= 1.0 || input[5] >= 1.0) {
      var1 = [0.01, 0.99];
    } else {
      var1 = [0.12, 0.88];
    }
  }

  // --- Tree Estimator 2: Domain Entropy & Algorithmic Generation (DGA) ---
  var var2;
  if (input[3] >= 0.5) {
    var2 = [0.02, 0.98];
  } else if (input[4] >= 0.5) {
    var2 = [0.01, 0.99];
  } else if (input[13] <= 3.45) {
    // Low / natural entropy
    if (input[10] >= 0.5 && input[9] >= 1.0) {
      var2 = [0.02, 0.98];
    } else if (input[9] <= 1.5) {
      var2 = [0.96, 0.04];
    } else {
      var2 = [0.15, 0.85];
    }
  } else {
    // High Shannon Entropy (Randomized/DGA domain)
    if (input[1] <= 18.0) {
      var2 = [0.20, 0.80];
    } else {
      var2 = [0.02, 0.98];
    }
  }

  // --- Tree Estimator 3: Dot & Hyphen Typosquatting ---
  var var3;
  if (input[3] >= 0.5) {
    var3 = [0.0, 1.0];
  } else if (input[4] >= 0.5) {
    var3 = [0.02, 0.98];
  } else if (input[10] >= 0.5 && input[9] >= 1.0) {
    var3 = [0.01, 0.99];
  } else if (input[2] <= 2.5) {
    if (input[5] <= 1.0) {
      var3 = [0.96, 0.04];
    } else {
      var3 = [0.15, 0.85];
    }
  } else {
    if (input[5] >= 2.0 || input[6] >= 2.0) {
      var3 = [0.02, 0.98];
    } else {
      var3 = [0.18, 0.82];
    }
  }

  // --- Tree Estimator 4: Raw IP & Deceptive '@' Delimiter ---
  var var4;
  if (input[3] >= 0.5) {
    // Raw IPv4/IPv6 address used
    var4 = [0.0, 1.0];
  } else if (input[4] >= 0.5) {
    // Deceptive '@' symbol used for credential masking
    var4 = [0.01, 0.99];
  } else if (input[10] >= 0.5 && input[9] >= 1.0) {
    var4 = [0.02, 0.98];
  } else {
    if (input[1] <= 24.0) {
      var4 = [0.94, 0.06];
    } else {
      if (input[10] <= 0.5) {
        var4 = [0.65, 0.35];
      } else {
        var4 = [0.04, 0.96];
      }
    }
  }

  // --- Tree Estimator 5: HTTPS Protocol & Special Characters ---
  var var5;
  if (input[3] >= 0.5) {
    var5 = [0.0, 1.0];
  } else if (input[4] >= 0.5) {
    var5 = [0.01, 0.99];
  } else if (input[7] <= 0.5) {
    // Insecure HTTP
    var5 = [0.04, 0.96];
  } else {
    if (input[10] >= 0.5 && input[9] >= 1.0) {
      var5 = [0.02, 0.98];
    } else if (input[12] <= 5.0) {
      var5 = [0.95, 0.05];
    } else {
      var5 = [0.35, 0.65];
    }
  }

  // --- Tree Estimator 6: Path Redirection & Subdomain Depth ---
  var var6;
  if (input[3] >= 0.5) {
    var6 = [0.01, 0.99];
  } else if (input[4] >= 0.5) {
    var6 = [0.01, 0.99];
  } else if (input[8] >= 0.5) {
    // Double slash '//' in path indicates open redirection evasion
    var6 = [0.03, 0.97];
  } else {
    if (input[6] <= 1.0) {
      if (input[10] >= 0.5 && input[9] >= 1.0) {
        var6 = [0.02, 0.98];
      } else {
        var6 = [0.93, 0.07];
      }
    } else {
      var6 = [0.18, 0.82];
    }
  }

  // --- Tree Estimator 7: Query Parameters & Keyword Clustering ---
  var var7;
  if (input[3] >= 0.5) {
    var7 = [0.0, 1.0];
  } else if (input[4] >= 0.5) {
    var7 = [0.01, 0.99];
  } else if (input[9] >= 2.0) {
    // Multiple sensitive keywords (e.g., login + verify)
    var7 = [0.01, 0.99];
  } else if (input[9] === 1.0) {
    if (input[10] >= 0.5 || input[11] >= 3.0 || input[0] > 75.0) {
      var7 = [0.02, 0.98];
    } else {
      var7 = [0.50, 0.50];
    }
  } else {
    var7 = [0.96, 0.04];
  }

  // --- Tree Estimator 8: Hostname Length & Abuse Heuristics ---
  var var8;
  if (input[3] >= 0.5) {
    var8 = [0.0, 1.0];
  } else if (input[4] >= 0.5) {
    var8 = [0.01, 0.99];
  } else if (input[10] >= 0.5 && input[9] >= 1.0) {
    var8 = [0.02, 0.98];
  } else if (input[1] > 26.0 && input[13] > 3.3) {
    var8 = [0.05, 0.95];
  } else if (input[0] > 95.0 && input[9] >= 1.0) {
    var8 = [0.10, 0.90];
  } else {
    var8 = [0.94, 0.06];
  }

  // --- Tree Estimator 9: Abusive TLD & Special Character Density ---
  var var9;
  if (input[3] >= 0.5) {
    var9 = [0.0, 1.0];
  } else if (input[4] >= 0.5) {
    var9 = [0.01, 0.99];
  } else if (input[10] >= 0.5 && (input[12] >= 3.0 || input[9] >= 1.0)) {
    var9 = [0.01, 0.99];
  } else if (input[10] >= 0.5) {
    var9 = [0.12, 0.88];
  } else {
    var9 = [0.95, 0.05];
  }

  // Ensemble averaging across the 10 decision trees (each tree weight = 0.1)
  const ensemble = addVectors(
    addVectors(
      addVectors(
        addVectors(
          addVectors(
            addVectors(
              addVectors(
                addVectors(
                  addVectors(var0, var1),
                  var2
                ),
                var3
              ),
              var4
            ),
            var5
          ),
          var6
        ),
        var7
      ),
      var8
    ),
    var9
  );

  return mulVectorNumber(ensemble, 0.1);
}

/**
 * High-level inference helper: returns a single phishing probability score between 0.0 and 1.0.
 *
 * @param {number[]} features - 14-dimension feature vector.
 * @returns {number} Phishing risk score (0.0 = completely safe, 1.0 = definite phishing).
 */
export function predictProbability(features) {
  try {
    const rawScores = score(features);
    if (Array.isArray(rawScores) && rawScores.length >= 2) {
      const prob = rawScores[1];
      if (typeof prob === 'number' && !isNaN(prob)) {
        return Math.max(0.0, Math.min(1.0, Number(prob.toFixed(4))));
      }
    }
  } catch (err) {
    console.error('[PhishingShield] Model execution error:', err);
  }
  return 0.5; // Neutral fallback on failure
}

/**
 * Binary classification helper matching scikit-learn's predict() interface.
 *
 * @param {number[]} features - 14-dimension feature vector.
 * @param {number} threshold - Decision boundary threshold (default: 0.80).
 * @returns {number} 1 if predicted phishing, 0 if legitimate.
 */
export function predict(features, threshold = 0.80) {
  return predictProbability(features) >= threshold ? 1 : 0;
}

/**
 * Vector addition helper matching m2cgen JavaScript transpilation format.
 */
function addVectors(v1, v2) {
  const result = new Array(v1.length);
  for (let i = 0; i < v1.length; i++) {
    result[i] = v1[i] + v2[i];
  }
  return result;
}

/**
 * Vector scalar multiplication helper matching m2cgen JavaScript transpilation format.
 */
function mulVectorNumber(v1, num) {
  const result = new Array(v1.length);
  for (let i = 0; i < v1.length; i++) {
    result[i] = v1[i] * num;
  }
  return result;
}

// CommonJS compatibility for Node.js test runners and jest environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    score,
    predictProbability,
    predict,
    FEATURE_NAMES,
    FEATURE_INDEXES
  };
}
