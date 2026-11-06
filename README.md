# SentinelAI · Local Security Operations

SentinelAI combines a Manifest V3 browser extension with a local security dashboard for URL investigation and phishing-model operations. The extension and dashboard use the same canonical 14-feature schema and the actual generated export of a fitted scikit-learn Random Forest.

URL parsing, feature extraction, inference, dataset handling, and training run on the user's machine. The optional browser-to-dashboard feed is **off by default**; when enabled, it sends only the visited URL to the loopback API at `127.0.0.1`, which independently re-scores it with the active local model. No remote threat-intelligence service is currently queried.

## What is included

- **Browser protection:** navigation scans, local risk scores, extension badge, whitelist, credential-input guard, and an isolated Shadow DOM warning.
- **Investigation agent:** accepts a URL and returns the trained model's class probabilities, exact model version, canonical features, URL-derived evidence, and scope limitations. It is a transparent local ML workflow, not a generative AI service.
- **Security dashboard:** overview, local investigation monitoring, URL investigation, investigation workflow, dataset explorer/import, model training, model registry/comparison/export, scan history, and local preferences.
- **Training service:** FastAPI endpoints backed by scikit-learn. Upload, validation, and cleaning are chunked; training/evaluation run in a Python worker and use registered-domain groups to reduce train/test leakage.
- **Model artifacts:** `ml/models/phishing_rf.joblib` is the fitted Python model; `ml/models/model_exported.js` is its generated browser inference export; `ml/models/model_metadata.json` records actual dataset, split, and evaluation details.

The reported performance is dataset- and split-specific, not a guarantee of future detection. See the current artifact's `evaluation_metrics` and `cross_validation_5_fold` fields for measured results.

## Run the dashboard and API

Python 3.10+ and Node.js are used by the local tooling and parity tests.

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements-platform.txt
uvicorn ml.platform_api:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The API binds to loopback only. Dataset upload is limited to 2 GiB and uses streamed writes; validation and cleaning process CSV chunks. Model fitting materializes features in memory, so available RAM and CPU constrain practical training dataset size.

### Dataset contract

Import a CSV with:

- `url`: an HTTP or HTTPS URL with a hostname
- `label`: `0`/`1`, `benign`/`phishing`, or the supported `legit`/`malicious` aliases
- optional `domain_group`: registered domain / eTLD+1 used for grouped evaluation

The dataset explorer validates rows and class counts, previews records, and offers cleaning/deduplication. Training automatically prepares a cleaned copy and derives missing domain groups using local suffix data without network lookups. Keep the provenance and license/usage terms of imported datasets.

### Training and deployment

In the Training Lab, choose a local CSV and configure the Random Forest tree count and maximum depth. The service reports real held-out accuracy, precision, recall, F1, ROC-AUC, PR-AUC, false-positive/negative rates, confusion matrix, and grouped cross-validation metrics. It stores versioned `.joblib`, JavaScript, and metadata artifacts under `ml/models/registry/`, then deploys the trained model to the active local API and the extension's `ml/models/model_exported.js` path.

If Chrome already has the extension loaded, reload it from `chrome://extensions/` to load a newly deployed JavaScript model. The registry offers version comparison and JavaScript export.

## Load the browser extension

1. Open `chrome://extensions/` and enable **Developer mode**.
2. Select **Load unpacked** and choose this repository directory.
3. Use the extension popup to inspect the active tab, rescan, and manage its whitelist.
4. Optionally start the local dashboard and enable **Live console sync** in the popup. This opt-in forwards scanned URLs only to `http://127.0.0.1:8000`; it remains disabled unless explicitly enabled.

The extension's `ml/models/model_exported.js` is generated from the fitted Random Forest. `model.js` remains only as a backwards-compatible entry point; the extension does not use the former hand-written scoring heuristic.

## Feature schema

The shared schema in [ml/canonical_schema.json](./ml/canonical_schema.json) defines the feature names/order. Python training uses [ml/features.py](./ml/features.py); browser inference and the demonstration page use [ml/features.js](./ml/features.js).

| Index | Feature |
|---:|---|
| 0 | `url_length` |
| 1 | `domain_length` |
| 2 | `num_dots` |
| 3 | `has_ip` |
| 4 | `has_at_symbol` |
| 5 | `num_hyphens` |
| 6 | `num_subdomains` |
| 7 | `is_https` |
| 8 | `has_double_slash_in_path` |
| 9 | `num_suspicious_keywords` |
| 10 | `has_suspicious_tld` |
| 11 | `num_query_params` |
| 12 | `special_char_count` |
| 13 | `domain_entropy` |

## Validation

Run the focused schema, inference, and local API tests:

```bash
./venv/bin/python -m pytest tests -q
node --check background.js
node --check popup/popup.js
node --check dashboard/dashboard.js
```

The model-export parity test compares JavaScript probabilities to the fitted Python artifact on representative benign and phishing URLs.

## Dataset sources

The checked-in dataset documentation identifies the phishing feeds and benign-domain source used to construct the current training CSV. Dataset construction/download logic lives in [ml/dataset.py](./ml/dataset.py); it is separate from dashboard startup and does not run unless explicitly requested.
