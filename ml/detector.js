/**
 * SentinelAI: Phishing & Scam Link Shield
 * Multi-Signal Detection Engine & Attack Chain Reasoner
 *
 * Combines:
 * 1. Canonical 14-feature URL lexical metrics + trained Random Forest model.
 * 2. Homograph / Punycode / IDN spoofing detection.
 * 3. Brand impersonation & typosquatting detection (Levenshtein + subdomain abuse).
 * 4. DOM / Form credential safety inspection (password destinations, title/brand mismatch).
 * 5. Attack Chain / Scam Story formulation (facts vs inferred possibilities).
 * 6. Standardized verdict with calibrated confidence, evidence categories, and unverified signals.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelDetector = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Known brand registry for impersonation detection
  const BRAND_REGISTRY = [
    {
      name: 'Google',
      canonicalDomains: ['google.com', 'google.co.uk', 'google.ca', 'google.de', 'google.fr', 'google.com.au', 'google.co.in', 'accounts.google.com'],
      keywords: ['google', 'gmail', 'googledrive', 'googleworkspace'],
      category: 'Technology & Identity'
    },
    {
      name: 'Microsoft',
      canonicalDomains: ['microsoft.com', 'office.com', 'live.com', 'outlook.com', 'office365.com', 'login.microsoftonline.com', 'azure.com'],
      keywords: ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'azure'],
      category: 'Enterprise & Cloud'
    },
    {
      name: 'Apple',
      canonicalDomains: ['apple.com', 'icloud.com', 'appleid.apple.com'],
      keywords: ['apple', 'appleid', 'icloud', 'itunes'],
      category: 'Consumer Technology'
    },
    {
      name: 'Amazon',
      canonicalDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp', 'aws.amazon.com', 'aboutamazon.com'],
      keywords: ['amazon', 'aws', 'primevideo'],
      category: 'E-Commerce & Cloud'
    },
    {
      name: 'PayPal',
      canonicalDomains: ['paypal.com', 'paypal.me'],
      keywords: ['paypal', 'paypalme'],
      category: 'Financial Services'
    },
    {
      name: 'Meta / Facebook',
      canonicalDomains: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'messenger.com'],
      keywords: ['facebook', 'instagram', 'whatsapp', 'meta'],
      category: 'Social Media'
    },
    {
      name: 'Netflix',
      canonicalDomains: ['netflix.com'],
      keywords: ['netflix'],
      category: 'Entertainment & Streaming'
    },
    {
      name: 'Chase Bank',
      canonicalDomains: ['chase.com'],
      keywords: ['chase', 'chasebank'],
      category: 'Banking'
    },
    {
      name: 'Bank of America',
      canonicalDomains: ['bankofamerica.com', 'bofa.com'],
      keywords: ['bankofamerica', 'bofa'],
      category: 'Banking'
    },
    {
      name: 'Wells Fargo',
      canonicalDomains: ['wellsfargo.com'],
      keywords: ['wellsfargo'],
      category: 'Banking'
    },
    {
      name: 'Coinbase',
      canonicalDomains: ['coinbase.com'],
      keywords: ['coinbase'],
      category: 'Cryptocurrency'
    },
    {
      name: 'Binance',
      canonicalDomains: ['binance.com'],
      keywords: ['binance'],
      category: 'Cryptocurrency'
    },
    {
      name: 'Steam / Valve',
      canonicalDomains: ['steampowered.com', 'steamcommunity.com', 'valvesoftware.com'],
      keywords: ['steam', 'steampowered', 'steamcommunity'],
      category: 'Gaming'
    },
    {
      name: 'DocuSign',
      canonicalDomains: ['docusign.com', 'docusign.net'],
      keywords: ['docusign'],
      category: 'Productivity & Legal'
    },
    {
      name: 'DHL',
      canonicalDomains: ['dhl.com', 'dhl.de'],
      keywords: ['dhl', 'dhl-express', 'dhlexpress'],
      category: 'Logistics & Shipping'
    },
    {
      name: 'USPS',
      canonicalDomains: ['usps.com'],
      keywords: ['usps'],
      category: 'Logistics & Shipping'
    }
  ];

  // Cyrillic and Greek homoglyphs commonly used in IDN spoofing
  const HOMOGLYPH_MAP = {
    '\u0430': 'a', // Cyrillic Small Letter A
    '\u0441': 'c', // Cyrillic Small Letter Es
    '\u0435': 'e', // Cyrillic Small Letter Ie
    '\u0456': 'i', // Cyrillic Small Letter Byelorussian-Ukrainian I
    '\u0458': 'j', // Cyrillic Small Letter Je
    '\u043E': 'o', // Cyrillic Small Letter O
    '\u0440': 'p', // Cyrillic Small Letter Er
    '\u0455': 's', // Cyrillic Small Letter Dze
    '\u0443': 'y', // Cyrillic Small Letter U
    '\u0445': 'x', // Cyrillic Small Letter Ha
    '\u03BF': 'o', // Greek Small Letter Omicron
    '\u03C1': 'p', // Greek Small Letter Rho
    '\u03BD': 'v'  // Greek Small Letter Nu
  };

  /**
   * Computes Levenshtein Distance between two strings.
   */
  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;

    const row = [];
    for (let i = 0; i <= b.length; i++) row[i] = i;

    for (let i = 1; i <= a.length; i++) {
      let prev = i;
      for (let j = 1; j <= b.length; j++) {
        let val;
        if (a[i - 1] === b[j - 1]) {
          val = row[j - 1];
        } else {
          val = Math.min(row[j - 1] + 1, prev + 1, row[j] + 1);
        }
        row[j - 1] = prev;
        prev = val;
      }
      row[b.length] = prev;
    }
    return row[b.length];
  }

  /**
   * Detects Unicode homoglyphs and Punycode (IDN) spoofing.
   */
  function detectHomoglyphs(hostname) {
    const raw = (hostname || '').toLowerCase();
    const findings = [];
    let isPunycode = false;
    let decodedHost = raw;

    if (raw.includes('xn--')) {
      isPunycode = true;
      findings.push({
        type: 'PUNYCODE_DOMAIN',
        severity: 'high',
        detail: `Internationalized Domain Name (Punycode: ${raw}) detected. Often used to disguise lookalike characters.`
      });
    }

    // Check for mixed-script homoglyphs
    let hasHomoglyphChar = false;
    const replaced = [];
    for (let i = 0; i < raw.length; i++) {
      const char = raw[i];
      if (HOMOGLYPH_MAP[char]) {
        hasHomoglyphChar = true;
        replaced.push(HOMOGLYPH_MAP[char]);
      } else {
        replaced.push(char);
      }
    }

    if (hasHomoglyphChar) {
      const normalizedString = replaced.join('');
      findings.push({
        type: 'HOMOGLYPH_SUBSTITUTION',
        severity: 'high',
        detail: `Domain uses lookalike non-Latin characters. Normalized visual appearance: "${normalizedString}".`
      });
    }

    return {
      isPunycode,
      hasHomoglyphs: findings.length > 0,
      findings
    };
  }

  /**
   * Determines if a hostname is an exact match or valid subdomain of a canonical domain.
   */
  function isCanonicalDomainMatch(hostname, canonicalDomains) {
    const cleanHost = hostname.toLowerCase();
    return canonicalDomains.some(canon => {
      const c = canon.toLowerCase();
      return cleanHost === c || cleanHost.endsWith('.' + c);
    });
  }

  /**
   * Detects brand impersonation, deceptive subdomains, and typosquatting.
   */
  function detectBrandImpersonation(url, hostname, pageTitle = '') {
    const host = (hostname || '').toLowerCase();
    const full = (url || '').toLowerCase();
    const title = (pageTitle || '').toLowerCase();
    const findings = [];
    let matchedBrand = null;

    // Remove port if present
    const cleanHost = host.split(':')[0];
    const hostParts = cleanHost.split('.').filter(Boolean);
    const domainBody = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : cleanHost;

    for (const brand of BRAND_REGISTRY) {
      const isLegitDomain = isCanonicalDomainMatch(cleanHost, brand.canonicalDomains);

      if (isLegitDomain) {
        // Legitimate site for this brand
        continue;
      }

      // 1. Brand name in subdomain of an unrelated domain
      // e.g. paypal.com.attacker-domain.xyz or secure-apple.login-portal.com
      const hostHasBrand = brand.keywords.some(kw => cleanHost.includes(kw));
      if (hostHasBrand) {
        matchedBrand = brand.name;
        findings.push({
          type: 'BRAND_SUBDOMAIN_MISMATCH',
          brand: brand.name,
          category: brand.category,
          severity: 'high',
          detail: `Brand "${brand.name}" appears in the hostname/subdomain, but the registered domain (${cleanHost}) is NOT an official ${brand.name} domain.`
        });
      }

      // 2. Typosquatting / Levenshtein distance on domain body
      // e.g. paypa1, micros0ft, arnazon
      for (const kw of brand.keywords) {
        if (kw.length >= 4 && domainBody.length >= 4) {
          const dist = levenshtein(domainBody, kw);
          if (dist === 1 || (dist === 2 && domainBody.length >= 7)) {
            matchedBrand = brand.name;
            findings.push({
              type: 'BRAND_TYPOSQUATTING',
              brand: brand.name,
              category: brand.category,
              severity: 'high',
              detail: `Possible typosquatting targeting "${brand.name}": domain "${domainBody}" differs from "${kw}" by only ${dist} character edit(s).`
            });
            break;
          }
        }
      }

      // 3. Page title claims brand identity on an unrelated domain
      if (title.length > 0) {
        const titleClaimsBrand = brand.keywords.some(kw => title.includes(kw));
        if (titleClaimsBrand && !hostHasBrand) {
          findings.push({
            type: 'TITLE_BRAND_DISCREPANCY',
            brand: brand.name,
            severity: 'medium',
            detail: `Page title claims to be "${brand.name}" ("${pageTitle.slice(0, 50)}..."), but the domain has no association with ${brand.name}.`
          });
        }
      }
    }

    return {
      isImpersonating: findings.length > 0,
      matchedBrand,
      findings
    };
  }

  /**
   * Analyzes DOM / form safety signals extracted from content script.
   */
  function evaluateDomSafety(domSignals, hostname) {
    const findings = [];
    if (!domSignals) return { findings, scoreAdjustment: 0 };

    const host = (hostname || '').toLowerCase();
    const {
      formCount = 0,
      passwordInputCount = 0,
      insecureForms = 0,
      crossOriginFormDestinations = [],
      ipFormDestinations = [],
      hasCreditCardField = false
    } = domSignals;

    if (passwordInputCount > 0 && ipFormDestinations.length > 0) {
      findings.push({
        type: 'PASSWORD_TO_IP_DESTINATION',
        severity: 'high',
        detail: `Critical Risk: Form with password inputs submits credentials directly to a raw IP destination (${ipFormDestinations[0]}).`
      });
    }

    if (insecureForms > 0 && passwordInputCount > 0) {
      findings.push({
        type: 'INSECURE_PASSWORD_TRANSMISSION',
        severity: 'high',
        detail: `Security Flaw: Password input is submitted over an unencrypted (HTTP) action destination.`
      });
    }

    if (passwordInputCount > 0 && crossOriginFormDestinations.length > 0) {
      const externalDest = crossOriginFormDestinations[0];
      findings.push({
        type: 'CROSS_ORIGIN_CREDENTIAL_FORM',
        severity: 'medium',
        detail: `Suspicious Form Target: Credentials on this page are submitted to an external third-party domain (${externalDest}).`
      });
    }

    return {
      findings,
      hasSensitiveInputs: passwordInputCount > 0 || hasCreditCardField
    };
  }

  /**
   * Formulates a structured Scam Story / Attack Chain clearly distinguishing facts from inferences.
   */
  function formulateAttackChain({ url, hostname, brandAnalysis, homographAnalysis, domAnalysis, lexicalFlags, mlProb }) {
    const observedFacts = [];
    let inferredTechnique = '';
    let potentialImpact = '';

    // Fact 1: Domain & Protocol
    if (url.startsWith('http://')) {
      observedFacts.push('Connection uses unencrypted HTTP protocol without transport security.');
    } else if (url.startsWith('https://')) {
      observedFacts.push('Connection uses HTTPS transport encryption.');
    }

    // Fact 2: Host identity
    if (homographAnalysis.isPunycode) {
      observedFacts.push(`Domain is encoded via Punycode (${hostname}).`);
    }
    if (brandAnalysis.isImpersonating) {
      observedFacts.push(`Domain mimics brand "${brandAnalysis.matchedBrand}" without belonging to its canonical infrastructure.`);
    }

    // Fact 3: Inputs & DOM
    if (domAnalysis?.findings?.length > 0) {
      domAnalysis.findings.forEach(f => observedFacts.push(f.detail));
    }

    // Fact 4: Lexical heuristics
    if (lexicalFlags && lexicalFlags.length > 0) {
      lexicalFlags.slice(0, 3).forEach(f => observedFacts.push(f));
    }

    // Inferred attack progression
    if (brandAnalysis.isImpersonating && (domAnalysis?.hasSensitiveInputs || mlProb > 0.6)) {
      inferredTechnique = `Attacker registers a visually deceptive domain mimicking ${brandAnalysis.matchedBrand} to lure victims from emails or messages into submitting account credentials.`;
      potentialImpact = `Credential harvesting, unauthorized access to user account at ${brandAnalysis.matchedBrand}, and potential identity compromise.`;
    } else if (homographAnalysis.hasHomoglyphs) {
      inferredTechnique = 'Attacker deploys lookalike Cyrillic or Greek characters to fool the user into believing they are on a legitimate corporate or financial portal.';
      potentialImpact = 'Deceptive redirection, credential harvesting, or unauthorized session hijacking.';
    } else if (mlProb > 0.75) {
      inferredTechnique = 'The URL structure exhibits high statistical correlation with known phishing campaigns (e.g. nested subdomains, credential keywords, or abnormal entropy).';
      potentialImpact = 'High probability of malicious intent; potential theft of personal information or financial data.';
    } else if (mlProb >= 0.40) {
      inferredTechnique = 'URL contains atypical structural characteristics that warrant user verification before proceeding.';
      potentialImpact = 'Caution advised; verify URL origin and avoid entering payment or login credentials.';
    } else {
      inferredTechnique = 'No recognized deceptive attack chain identified from URL structure and accessible signals.';
      potentialImpact = 'Standard web browsing risk. Always ensure you are on the intended official domain.';
    }

    return {
      observedFacts,
      inferredTechnique,
      potentialImpact
    };
  }

  /**
   * Actionable educational tips based on the specific threats detected.
   */
  function getScamCoachTip(brandAnalysis, homographAnalysis, domAnalysis, verdict) {
    if (brandAnalysis.isImpersonating) {
      return `Tip: Never log into ${brandAnalysis.matchedBrand} through links in emails or SMS. Instead, type ${brandAnalysis.matchedBrand.toLowerCase()}.com directly in your browser's address bar.`;
    }
    if (homographAnalysis.hasHomoglyphs) {
      return 'Tip: Cybercriminals use foreign alphabet characters that look identical to English letters (like Cyrillic "а" for Latin "a"). Always check the full domain spelling carefully.';
    }
    if (domAnalysis?.findings?.some(f => f.type.includes('PASSWORD'))) {
      return 'Tip: Legitimate websites almost never send passwords to raw numbers (IP addresses) or third-party domains. Never submit passwords on this page.';
    }
    if (verdict === 'suspicious') {
      return 'Tip: When a site looks unusual or requests immediate action to "verify your account", pause and contact the service through their official app or verified phone number.';
    }
    return 'Tip: Keep your browser updated, use multi-factor authentication (MFA) everywhere, and verify the domain name before typing passwords.';
  }

  /**
   * Constructs an interactive threat evidence graph representing relationships
   * between URL, Host, Protocol, Brand, and Form Destination.
   */
  function buildEvidenceGraph(url, hostname, brandAnalysis, domAnalysis, verdict) {
    const nodes = [
      { id: 'url', label: 'Requested URL', type: 'url', status: verdict === 'malicious' ? 'danger' : verdict === 'suspicious' ? 'warning' : 'neutral' },
      { id: 'host', label: hostname, type: 'hostname', status: brandAnalysis.isImpersonating ? 'danger' : 'neutral' }
    ];
    const edges = [
      { from: 'url', to: 'host', label: 'hosts on' }
    ];

    if (brandAnalysis.matchedBrand) {
      nodes.push({ id: 'brand', label: `Target: ${brandAnalysis.matchedBrand}`, type: 'brand', status: 'danger' });
      edges.push({ from: 'host', to: 'brand', label: 'impersonates' });
    }

    if (domAnalysis?.findings?.length > 0) {
      nodes.push({ id: 'form', label: 'Credential Form', type: 'dom', status: 'danger' });
      edges.push({ from: 'host', to: 'form', label: 'contains' });
    }

    return { nodes, edges };
  }

  /**
   * Comprehensive Multi-Signal Detection Evaluator.
   *
   * @param {Object} params
   * @param {string} params.url
   * @param {string} params.hostname
   * @param {number[]} params.features
   * @param {number[]} params.mlProbabilities - [p_benign, p_phishing]
   * @param {string[]} params.lexicalFlags
   * @param {Object} [params.domSignals]
   * @param {boolean} [params.isWhitelisted]
   * @param {string} [params.modelVersion]
   * @returns {Object} Complete standardized verdict report
   */
  function evaluateUrlSignals(params) {
    const {
      url,
      hostname,
      features,
      mlProbabilities = [0.5, 0.5],
      lexicalFlags = [],
      domSignals = null,
      isWhitelisted = false,
      modelVersion = 'rf-20261104-183213'
    } = params;

    const mlPhishingProb = typeof mlProbabilities[1] === 'number' ? mlProbabilities[1] : 0.5;

    // Check user whitelist first
    if (isWhitelisted) {
      return {
        verdict: 'safe',
        riskLevel: 'WHITELISTED',
        riskScore: 0.0,
        confidence: 1.0,
        whitelisted: true,
        summary: 'Domain is on your personal trusted whitelist.',
        evidence: [{ category: 'User Preference', title: 'Trusted Domain', detail: 'This domain was explicitly added to your personal trusted list.', severity: 'low' }],
        categoryScores: { lexical: 0, brand: 0, dom: 0, homograph: 0, mlModel: 0 },
        attackChain: { observedFacts: ['Domain trusted by user.'], inferredTechnique: 'None.', potentialImpact: 'None.' },
        signalsNotChecked: ['External Threat Intelligence feeds'],
        recommendedAction: 'Domain is trusted by user preference. Proceed as normal.',
        scamCoachTip: 'Whitelisted domains bypass automated warnings. You can remove it anytime in Settings.',
        evidenceGraph: { nodes: [{ id: 'host', label: hostname, type: 'hostname', status: 'safe' }], edges: [] },
        modelVersion,
        timestamp: Date.now()
      };
    }

    // 1. Analyze Homoglyphs & Punycode
    const homographAnalysis = detectHomoglyphs(hostname);

    // 2. Analyze Brand Impersonation & Typosquatting
    const brandAnalysis = detectBrandImpersonation(url, hostname, domSignals?.title || '');

    // 3. Analyze DOM / Form Credentials
    const domAnalysis = evaluateDomSafety(domSignals, hostname);

    // 4. Calculate Sub-Scores per Category
    let brandScore = 0.0;
    if (brandAnalysis.isImpersonating) brandScore = 0.90;

    let homographScore = 0.0;
    if (homographAnalysis.hasHomoglyphs) homographScore = 0.85;

    let domScore = 0.0;
    if (domAnalysis.findings.some(f => f.severity === 'high')) domScore = 0.95;
    else if (domAnalysis.findings.length > 0) domScore = 0.50;

    const lexicalScore = Math.min(1.0, (lexicalFlags.length * 0.25));

    // 5. Composite Risk Score Computation (Heuristics + ML Ensemble)
    // If brand impersonation or malicious DOM credential form is observed, it overrides lower lexical ML scores
    let compositeRisk = mlPhishingProb;
    if (brandScore > compositeRisk) compositeRisk = Math.max(compositeRisk, 0.85);
    if (homographScore > compositeRisk) compositeRisk = Math.max(compositeRisk, 0.80);
    if (domScore > compositeRisk) compositeRisk = Math.max(compositeRisk, 0.90);

    // Round score cleanly
    const finalRiskScore = Number(compositeRisk.toFixed(4));

    // 6. Verdict Determination
    // Support all 4 verdicts: 'safe' | 'suspicious' | 'malicious' | 'unknown'
    let verdict = 'safe';
    let riskLevel = 'SAFE';

    if (finalRiskScore >= 0.75) {
      verdict = 'malicious';
      riskLevel = 'RISK';
    } else if (finalRiskScore >= 0.40) {
      verdict = 'suspicious';
      riskLevel = 'WARN';
    } else if (finalRiskScore >= 0.15 && lexicalFlags.length === 0 && !domSignals) {
      // If score is ambiguous and we have no DOM signals or verified reputation
      verdict = 'unknown';
      riskLevel = 'WARN';
    } else {
      verdict = 'safe';
      riskLevel = 'SAFE';
    }

    // 7. Calibrated Confidence Calculation
    // Confidence is high when multiple signals agree, lower when signals are sparse or contradictory
    let confidence = 0.80;
    if (verdict === 'malicious') {
      confidence = (brandAnalysis.isImpersonating || domAnalysis.findings.length > 0) ? 0.95 : 0.88;
    } else if (verdict === 'unknown') {
      confidence = 0.45;
    } else {
      confidence = mlPhishingProb < 0.10 ? 0.92 : 0.75;
    }

    // 8. Compile Evidence List
    const evidence = [];

    brandAnalysis.findings.forEach(f => {
      evidence.push({ category: 'Brand Integrity', title: f.type, detail: f.detail, severity: f.severity });
    });

    homographAnalysis.findings.forEach(f => {
      evidence.push({ category: 'Domain Structure', title: f.type, detail: f.detail, severity: f.severity });
    });

    if (domAnalysis?.findings) {
      domAnalysis.findings.forEach(f => {
        evidence.push({ category: 'Form & DOM', title: f.type, detail: f.detail, severity: f.severity });
      });
    }

    lexicalFlags.forEach(flag => {
      evidence.push({ category: 'URL Pattern', title: 'URL Heuristic Signal', detail: flag, severity: 'medium' });
    });

    if (evidence.length === 0 && finalRiskScore >= 0.40) {
      evidence.push({
        category: 'Machine Learning',
        title: 'Statistical Pattern Match',
        detail: 'The trained Random Forest model identified structural correlations common to phishing links.',
        severity: 'medium'
      });
    }

    // 9. Formulate Attack Chain & Recommendations
    const attackChain = formulateAttackChain({
      url,
      hostname,
      brandAnalysis,
      homographAnalysis,
      domAnalysis,
      lexicalFlags,
      mlProb: finalRiskScore
    });

    const scamCoachTip = getScamCoachTip(brandAnalysis, homographAnalysis, domAnalysis, verdict);
    const evidenceGraph = buildEvidenceGraph(url, hostname, brandAnalysis, domAnalysis, verdict);

    let recommendedAction = '';
    if (verdict === 'malicious') {
      recommendedAction = 'Do NOT enter credentials or personal data. Close this tab or return to safety immediately.';
    } else if (verdict === 'suspicious') {
      recommendedAction = 'Proceed with heightened caution. Verify the sender and domain name before logging in.';
    } else if (verdict === 'unknown') {
      recommendedAction = 'Unverified website. Exercise standard caution and confirm domain authenticity before sharing sensitive info.';
    } else {
      recommendedAction = 'Low threat detected. URL structure and features appear legitimate.';
    }

    const signalsNotChecked = [
      'Live TLS certificate chain validation (requires native socket inspection)',
      'External Threat Intelligence API lookup (disabled or unconfigured)'
    ];
    if (!domSignals) {
      signalsNotChecked.push('DOM form destination inspection (page not yet rendered in tab)');
    }

    return {
      verdict,
      riskLevel,
      riskScore: finalRiskScore,
      confidence: Number(confidence.toFixed(2)),
      whitelisted: false,
      summary: verdict === 'malicious'
        ? 'Critical Threat: Deceptive signals indicate high phishing risk.'
        : verdict === 'suspicious'
          ? 'Warning: Suspicious characteristics detected that warrant caution.'
          : verdict === 'unknown'
            ? 'Unknown Status: Insufficient signals to declare safe or malicious.'
            : 'Low Risk: No deceptive patterns or malicious heuristics observed.',
      evidence,
      categoryScores: {
        lexical: Number(lexicalScore.toFixed(2)),
        brand: Number(brandScore.toFixed(2)),
        dom: Number(domScore.toFixed(2)),
        homograph: Number(homographScore.toFixed(2)),
        mlModel: Number(mlPhishingProb.toFixed(2))
      },
      attackChain,
      signalsNotChecked,
      recommendedAction,
      scamCoachTip,
      evidenceGraph,
      brandMatch: brandAnalysis.matchedBrand || null,
      modelVersion,
      timestamp: Date.now()
    };
  }

  return {
    BRAND_REGISTRY,
    detectHomoglyphs,
    detectBrandImpersonation,
    evaluateDomSafety,
    formulateAttackChain,
    getScamCoachTip,
    buildEvidenceGraph,
    evaluateUrlSignals
  };
});
