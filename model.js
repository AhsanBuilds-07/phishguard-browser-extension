/**
 * SentinelAI: Phishing & Scam Link Shield
 * Unified Model & Detection Engine Loader
 *
 * Provides a clean entry point for both Service Worker and Node.js environments.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const features = require('./ml/features.js');
    const model = require('./ml/models/model_exported.js');
    const detector = require('./ml/detector.js');
    module.exports = { ...model, features, detector };
  } else {
    // In Browser Service Worker, dependencies are loaded via importScripts
    root.Sentinel = root.Sentinel || {};
    if (root.SentinelModel) {
      root.predictPhishingScore = root.SentinelModel.predictPhishingScore;
    }
  }
})(typeof self !== 'undefined' ? self : this);
