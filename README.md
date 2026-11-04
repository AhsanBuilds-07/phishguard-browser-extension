# PhishingShieldExtension 🛡️

A privacy-first, high-performance Chrome Extension (Manifest V3) designed to detect phishing, fraudulent websites, and brand mimicry scams entirely **locally on-device** using machine learning and DOM heuristics.

---

## 🚀 Key Architectural Features

- **100% Client-Side On-Device Inference**:
  Zero browsing telemetry or URL data ever leaves the user's browser. ML predictions execute purely in-memory within the Chrome background service worker.
- **Manifest V3 Architecture**:
  Utilizes the modern Service Worker lifecycle, Content Scripts, and declarative permissions (`tabs`, `activeTab`, `scripting`, `storage`).
- **Transpiled ML Model (`m2cgen`)**:
  A Scikit-Learn `RandomForestClassifier` trained on lexical, structural, and semantic URL characteristics is compiled directly to pure JavaScript (`ml/model.js`). Sub-millisecond execution with **zero external dependencies** (no heavy WebAssembly, ONNX, or TensorFlow.js runtimes).
- **Deep DOM & Brand Mimicry Inspection**:
  The injected content script examines login forms, password inputs over unencrypted HTTP, cross-domain form post submissions, hidden credential harvesters, and checks whether high-profile brands (PayPal, Apple, Google, Microsoft, Chase, Bank of America, etc.) are being impersonated on unauthorized domains.
- **Shadow DOM In-Page Security Shield**:
  In-page warnings are rendered inside an isolated Shadow Root so that malicious website stylesheets cannot hide, tamper with, or override the security banner.

---

## 📁 File Structure

```
PhishingSheild/
├── manifest.json              # Chrome Manifest V3 configuration
├── background.js              # Service worker: intercepts navigation, extracts features, runs ML
├── content.js                 # Content script: inspects DOM, forms, and brand mimicry
├── content.css                # Content script styles
├── popup/
│   ├── popup.html             # Clean modern popup UI (safety gauge, risk breakdown)
│   ├── popup.js               # Popup controller & messaging bridge
│   └── popup.css              # Custom styling for popup UI
├── ml/
│   ├── train_phishing_model.ipynb # Jupyter Notebook for RF training & m2cgen transpilation
│   └── model.js               # Transpiled zero-dependency JavaScript model
└── icons/
    ├── icon16.png             # 16x16 extension icon
    ├── icon48.png             # 48x48 extension icon
    └── icon128.png            # 128x128 extension icon
```

---

## 🔄 Data Flow & Threat Detection Pipeline

```
[User Navigates Tab]
         │
         ▼
[background.js] (Service Worker)
  ├── 1. Intercepts chrome.tabs.onUpdated
  ├── 2. Extracts 14 Lexical/Structural URL features
  ├── 3. Executes Local ML Model: score(features) -> [probLegit, probPhishing]
  └── 4. Sets Extension Badge (Green 'OK' / Amber '!' / Red '!!!')
         │
         ▼
[content.js] (DOM Inspector)
  ├── 1. Injected at document_idle
  ├── 2. Inspects password fields, form action targets, hidden inputs
  ├── 3. Evaluates Brand Mimicry (Page Title/Headers vs. Canonical Hostname)
  └── 4. Dispatches 'DOM_ANALYSIS_RESULT' to background.js
         │
         ▼
[Composite Risk Assessment] (background.js)
  ├── Synthesizes URL ML score + DOM heuristics
  └── If Risk >= 70% or Brand Spoofing detected:
       └── Sends 'TRIGGER_PAGE_WARNING' to content.js -> Renders Shadow DOM Modal
         │
         ▼
[popup/popup.html] (User Interface)
  └── Queries background.js via 'GET_TAB_ASSESSMENT' to display circular threat gauge,
      status badges, vector breakdown, and whitelist controls.
```

---

## 🧪 Extracted URL Feature Vector (14 Dimensions)

The feature extractor in `background.js` and `ml/train_phishing_model.ipynb` produces an aligned 14-dimensional vector:

| Index | Feature | Type | Description |
|---|---|---|---|
| 0 | `url_length` | Integer | Total character length of URL |
| 1 | `domain_length` | Integer | Character length of the hostname |
| 2 | `num_dots` | Integer | Count of periods in hostname |
| 3 | `has_ip` | Binary (0/1) | Whether hostname is a raw IPv4/IPv6 address |
| 4 | `has_at_symbol` | Binary (0/1) | Presence of `@` credential-masking character |
| 5 | `num_hyphens` | Integer | Count of hyphens in domain (typosquatting indicator) |
| 6 | `num_subdomains` | Integer | Count of subdomain levels |
| 7 | `is_https` | Binary (0/1) | Protocol is HTTPS |
| 8 | `has_double_slash` | Binary (0/1) | Path contains `//` redirection sequence |
| 9 | `num_keywords` | Integer | Sensitive keywords (`login`, `verify`, `banking`, etc.) |
| 10 | `has_suspicious_tld` | Binary (0/1) | High-abuse TLD (`.xyz`, `.top`, `.tk`, etc.) |
| 11 | `num_query_params` | Integer | Number of query string keys |
| 12 | `special_char_count`| Integer | Count of `%`, `&`, `=`, `?`, `_`, `~` |
| 13 | `domain_entropy` | Float | Shannon entropy of domain (DGA / randomized domains) |

---

## 🛠️ Installation & Testing in Google Chrome

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle switch in the upper-right corner.
3. Click the **Load unpacked** button.
4. Select the `PhishingSheild` workspace directory (`/home/ahesanali/Desktop/PhishingSheild`).
5. The extension **PhishingShieldExtension** will now appear in your extensions list and toolbar.

### Test Cases to Verify
- **Legitimate Site**: Navigate to `https://www.google.com` or `https://github.com`.
  - Badge displays green `OK`.
  - Popup shows `0% - 10% Threat Score` with `SAFE & VERIFIED`.
- **Suspicious Structure**: Navigate to an HTTP test URL with multiple subdomains.
  - Badge displays amber `!`.
- **Phishing Simulation**: Open a test HTML page or local server with title `PayPal Login` hosted on `localhost` or an unauthorized domain.
  - The in-page Shadow DOM modal triggers warning the user of **Brand Impersonation**.
  - Badge displays red `!!!`.

---

## 🧠 Retraining the Machine Learning Model

To retrain the Random Forest model or adjust feature weights:
1. Activate your Python environment:
   ```bash
   source venv/bin/activate
   ```
2. Launch Jupyter Lab / Notebook:
   ```bash
   jupyter notebook ml/train_phishing_model.ipynb
   ```
3. Run all cells:
   - Evaluates accuracy, confusion matrix, and feature importances.
   - Automatically transpiles the trained model via `m2cgen` directly into `ml/model.js`.
