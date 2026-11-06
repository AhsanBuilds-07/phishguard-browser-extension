# SentinelAI Training Dataset Documentation

## Overview
- **Total Samples:** 8000
- **Phishing Samples (label=1):** 4000
- **Benign Samples (label=0):** 4000
- **Unique Domain Groups:** 5382

## Sources
1. **Phishing URLs:**
   - [Phishing.Database Active Feed](https://github.com/mitchellkrogza/Phishing.Database)
   - [OpenPhish Public Community Feed](https://openphish.com)
2. **Benign URLs:**
   - [Majestic Million](https://majestic.com/reports/majestic-million) top ranked domains with realistic path, subdomain, and query parameter distribution to prevent root-domain path bias.

## Data Leakage Prevention
Every URL is tagged with its registered domain / eTLD+1 (`domain_group`).
Train/test splitting is performed strictly via `GroupShuffleSplit` and `GroupKFold` on `domain_group`, ensuring zero domain overlap between training and evaluation splits.
