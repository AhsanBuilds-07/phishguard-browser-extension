/**
 * SentinelAI web scanner
 *
 * Browser-side mirror of investigateUrl() in background.js so the public site
 * (landing hero, demo testbench) runs the exact same on-device pipeline:
 * canonical features -> Random Forest -> multi-signal detector.
 *
 * Requires ml/features.js, ml/models/model_exported.js and ml/detector.js.
 */
(function (root) {
  'use strict';

  function lexicalFlagsFor(f) {
    const flags = [];
    if (f.has_ip === 1) flags.push('Raw IP address used instead of domain name');
    if (f.has_at_symbol === 1) flags.push('Contains "@" credential-masking delimiter');
    if (f.is_https === 0) flags.push('Unencrypted connection (insecure HTTP scheme)');
    if (f.has_suspicious_tld === 1) flags.push('High-abuse Top-Level Domain commonly used in phishing');
    if (f.num_suspicious_keywords > 0) flags.push(`Authentication or banking keywords detected (${f.num_suspicious_keywords} matches)`);
    if (f.num_subdomains >= 2) flags.push(`Excessive subdomain depth (${f.num_subdomains} levels)`);
    if (f.num_hyphens >= 2) flags.push(`Excessive hyphens in hostname (${f.num_hyphens}) - typosquatting signal`);
    if (f.domain_entropy > 3.5) flags.push(`High algorithmic domain randomness (Entropy: ${f.domain_entropy})`);
    if (f.has_double_slash_in_path === 1) flags.push('Open redirection path evasion pattern (//)');
    return flags;
  }

  function investigate(rawUrl) {
    const featureAPI = root.SentinelFeatures;
    const modelAPI = root.SentinelModel;
    const detectorAPI = root.SentinelDetector;
    if (!featureAPI || !modelAPI || !detectorAPI) {
      throw new Error('Detection modules failed to load.');
    }

    let cleanUrl = (rawUrl || '').trim();
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(cleanUrl)) cleanUrl = `http://${cleanUrl}`;

    let hostname = '';
    try {
      hostname = (new URL(cleanUrl).hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
    } catch (e) {
      throw new Error('Enter a valid HTTP or HTTPS URL.');
    }
    if (!hostname) throw new Error('URL must contain a hostname.');

    const started = performance.now();
    const featureArray = featureAPI.extractFeatures(cleanUrl);
    const features = featureAPI.extractFeaturesDict(cleanUrl);
    const lexicalFlags = lexicalFlagsFor(features);
    const mlProbabilities = modelAPI.predictProba(featureArray);

    const report = detectorAPI.evaluateUrlSignals({
      url: cleanUrl,
      hostname,
      features: featureArray,
      mlProbabilities,
      lexicalFlags,
      domSignals: null,
      isWhitelisted: false,
      modelVersion: modelAPI.MODEL_VERSION
    });

    report.url = cleanUrl;
    report.hostname = hostname;
    report.features = features;
    report.featureArray = featureArray;
    report.lexicalFlags = lexicalFlags;
    report.probabilities = { benign: mlProbabilities[0], phishing: mlProbabilities[1] };
    report.modelVersion = modelAPI.MODEL_VERSION || report.modelVersion;
    report.elapsedMs = performance.now() - started;
    return report;
  }

  root.SentinelScan = { investigate, lexicalFlagsFor };
})(typeof self !== 'undefined' ? self : this);
