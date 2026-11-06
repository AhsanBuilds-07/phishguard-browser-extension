/**
 * Compatibility entry point for consumers that used to load model.js.
 * The production model is generated from the fitted scikit-learn artifact.
 */
(function (root) {
  'use strict';

  if (typeof module === 'object' && module.exports) {
    module.exports = require('./ml/models/model_exported.js');
    return;
  }

  if (root.SentinelModel) {
    root.predictPhishingScore = root.SentinelModel.predictPhishingScore;
    return;
  }

  throw new Error('Load ml/models/model_exported.js before the model.js compatibility entry point.');
})(typeof self !== 'undefined' ? self : this);
