# SentinelAI · Autonomous Cyber Defense & Link Shield

SentinelAI is an on-device cybersecurity platform and Chrome Extension (Manifest V3) engineered for real-time phishing, deceptive brand impersonation, and credential harvesting defense.

Unlike cloud-dependent extensions, SentinelAI executes its entire multi-signal detection pipeline on-device within the browser’s V8 engine:
- **Zero telemetry**: Browsing URLs and navigation history are never transmitted to external servers.
- **Sub-millisecond inference**: A Random Forest ensemble transpiled via `m2cgen` executes with zero external dependencies.
- **Explainable threat reasoning**: Transparent attack chain modeling distinguishes observed facts from inferred risks.

---

## Architecture & Detection Engine

```
[ Web Navigation Event ]
           │
           ▼
┌────────────────────────────────────────────────────────┐
│              SentinelAI Detection Pipeline             │
├────────────────────────────────────────────────────────┤
│ 1. Canonical Lexical Extractor (14 Features)           │
│ 2. Scikit-Learn Random Forest On-Device Inference      │
│ 3. Brand Impersonation & Typosquatting Matcher         │
│ 4. Unicode / Punycode Homoglyph Detector               │
│ 5. DOM & Credential Destination Validator              │
└────────────────────────────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────────────────┐
│ Standardized Multi-Signal Verdict                      │
│ - Verdict: Safe | Suspicious | Malicious | Unknown     │
│ - Risk Score: 0.0 to 1.0 (Calibrated Confidence %)     │
│ - Attack Chain: Observed Facts vs Inferred Possibility │
│ - Evidence Dossier: Brand, Lexical, DOM, Homoglyph     │
│ - Scam Awareness Coach Tip & Reversible Override       │
└────────────────────────────────────────────────────────┘
```

---

## Distinctive Capabilities vs. Industry Competitors

SentinelAI provides a distinctive, transparent approach to browser security:

| Capability | SentinelAI Link Shield | Typical Cloud Extensions (e.g. VT4Browsers, Guardio) |
| :--- | :--- | :--- |
| **Data Privacy** | **100% On-Device**; zero URLs or browsing history leave browser | URLs uploaded to cloud servers for lookup |
| **Brand Impersonation** | Subdomain abuse + Levenshtein typosquatting against 16 protected brands | Visual DOM screenshot comparison (heavy compute) or cloud DB |
| **Inference Latency** | **< 1 ms** client-side V8 execution | 150 ms – 1500 ms roundtrip cloud network latency |
| **Explainability** | Detailed Attack Chain separating verified facts from inferences | Opaque score or binary block screen |
| **User Override** | Reversible session override with persistent floating safety pill | Permanent bypass or hard lock breaking workflows |
| **Model Governance** | Built-in ML Training Lab, Dataset Explorer & Model Registry | Proprietary black-box cloud model |

---

## 11 Dashboard Pages

Access the full Cybersecurity Command Center via `chrome.runtime.openOptionsPage()`, the extension popup ("Open Security Command Center"), or directly via loopback (`http://127.0.0.1:8000`):

1. **Overview / Security Command Center**: Operational threat posture, active model status, and verdict distribution.
2. **Live Browser Monitor**: Real-time event stream of active and background tab navigations with deduplicated tab binding.
3. **AI Threat Investigation**: Deep-dive URL analysis with attack chain, verified evidence cards, and JSON export.
4. **URL & Domain Analyzer**: Structural dissection of scheme, eTLD+1, Shannon entropy meter, and Punycode decoder.
5. **Threat Intelligence**: Configurable external feeds (VirusTotal, Google Safe Browsing) with masked local key storage.
6. **Dataset Explorer**: Inspect real-world training datasets (Phishing.Database, Majestic Million) and benchmark metadata (UCI Phishing, PhiUSIIL).
7. **ML Training Lab**: Local Python worker executing domain-aware training (`GroupShuffleSplit` on eTLD+1) and `m2cgen` JavaScript export.
8. **Model Registry**: Versioned model registry with 1-click activation, rollback, and side-by-side metric comparisons.
9. **Scan History**: Searchable, filterable audit trail by verdict with JSON/CSV export.
10. **Privacy Center**: Transparent data flow map, zero-telemetry guarantee, and local false positive/negative feedback.
11. **Settings**: Detection thresholds (Warning/Risk), personal whitelist manager, and UI appearance toggles.

---

## Canonical 14-Feature Schema

Every model training run and browser inference invocation uses the identical canonical feature schema defined in [`ml/canonical_schema.json`](./ml/canonical_schema.json):

```
Index  Feature Name               Type     Description
-------------------------------------------------------------------------------------------------------
 [0]   url_length                 int      Total character length of URL (lowercased).
 [1]   domain_length              int      Character length of hostname.
 [2]   num_dots                   int      Dot count in hostname (fake subdomains indicator).
 [3]   has_ip                     0 | 1    1 if hostname is a raw IPv4 or IPv6 address.
 [4]   has_at_symbol              0 | 1    1 if '@' credential-masking delimiter is in URL.
 [5]   num_hyphens                int      Count of '-' in hostname (typosquatting indicator).
 [6]   num_subdomains             int      Subdomain depth beyond eTLD+1 root.
 [7]   is_https                   0 | 1    1 if protocol is HTTPS, 0 for HTTP/insecure.
 [8]   has_double_slash_in_path   0 | 1    1 if '//' appears in pathname (redirect evasion).
 [9]   num_suspicious_keywords    int      Count of matched authentication/banking keywords.
 [10]  has_suspicious_tld         0 | 1    1 if TLD is in high-abuse set (.xyz, .top, .tk, etc.).
 [11]  num_query_params           int      Count of key-value query parameters.
 [12]  special_char_count         int      Count of special characters (%&=?_~) in full URL.
 [13]  domain_entropy             float    Shannon entropy of hostname (detects DGA domains).
```

---

## Installation & Running

### 1. Load the Chrome Extension (Manifest V3)
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in upper right).
3. Click **Load unpacked** and select the root directory: `/home/ahesanali/Desktop/PhishingSheild`.
4. The SentinelAI shield icon will appear in your extensions bar.
5. Click the shield icon on any tab to inspect the threat assessment or click **Open Security Command Center**.

### 2. Run the Local Backend & Dashboard Service (Optional)
The extension functions **100% offline** without the Python service. To run the ML Training Lab and backend API:

```bash
# Activate virtual environment
source venv/bin/activate

# Start loopback FastAPI service
uvicorn ml.platform_api:app --host 127.0.0.1 --port 8000
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in any browser.

### 3. Run the Automated Test Suite
```bash
# Run complete test suite (18 unit tests across Python & Node.js)
./venv/bin/python tests/run_all_tests.py

# Or run via pytest
./venv/bin/python -m pytest tests -v
```

---

## Model Evaluation (Held-Out Unseen Domains)

Trained on 8,000 balanced real-world URLs (4,000 verified phishing from Phishing.Database/OpenPhish, 4,000 benign from Majestic Million) evaluated strictly using `GroupShuffleSplit` on registered domains:

- **Accuracy:** 97.45%
- **Precision:** 99.72%
- **Recall (TPR):** 95.96%
- **F1-Score:** 97.80%
- **ROC-AUC:** 0.9995
- **False Positive Rate (FPR):** 0.39% (only 3 benign flagged out of 773)
- **False Negative Rate (FNR):** 4.04% (45 phishing missed out of 1,113)

---

## Known Limitations

1. **Compromised Reputable Cloud Infrastructure**: Phishing hosted on reputable platforms (`forms.google.com`, `workers.dev`, `storage.googleapis.com`) where the domain itself is benign relies primarily on path keywords and DOM inspection.
2. **URL Shorteners / Fast-Flux Redirects**: URL shorteners (`bit.ly`, `tinyurl.com`) hide destination features until HTTP redirects occur.
3. **Punycode / Advanced Homoglyphs**: Emerging Unicode confusables across non-Latin alphabets require continuous registry updates.
