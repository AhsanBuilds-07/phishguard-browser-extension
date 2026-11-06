"""
SentinelAI Phishing & Scam Link Shield
Dataset Ingestion & Preparation Pipeline

Downloads and curates verified, documented phishing URLs from:
  - Phishing.Database (Mitchell Krogza active feed)
  - OpenPhish public feed
And verified benign URLs from:
  - Majestic Million Top Domains (with realistic path & subdomain enrichment to eliminate path-absence bias)

Saves clean, balanced dataset with domain groups to ml/data/dataset.csv.
"""

import csv
import io
import os
import random
import re
import sys
import urllib.request
from typing import List, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from ml.features import extract_domain_group

DATA_DIR = os.path.join(ROOT_DIR, "ml", "data")
DATASET_CSV = os.path.join(DATA_DIR, "dataset.csv")

# Remote Data Source Endpoints
PHISHING_FEED_URLS = [
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "https://raw.githubusercontent.com/openphish/public_feed/master/feed.txt"
]
MAJESTIC_MILLION_URL = "https://downloads.majestic.com/majestic_million.csv"

# Realistic benign web structures to prevent trivial root-domain-only bias
BENIGN_PATH_TEMPLATES = [
    "",
    "/about",
    "/about-us",
    "/contact",
    "/privacy-policy",
    "/terms-of-service",
    "/blog",
    "/blog/recent-news",
    "/docs",
    "/docs/getting-started",
    "/products",
    "/products/item?id={rand_id}",
    "/category/technology?page={rand_page}",
    "/search?q=documentation",
    "/search?q=open-source+projects",
    "/articles/{rand_year}/spring-release",
    "/help/faq",
    "/support",
    "/pricing",
    "/careers",
    # Crucial hard negatives: legitimate sites also have authentication & accounts!
    "/login",
    "/signin",
    "/auth/login",
    "/account/overview",
    "/users/profile"
]

BENIGN_SUBDOMAINS = [
    "",
    "www",
    "blog",
    "docs",
    "api",
    "app",
    "support",
    "help",
    "cdn",
    "mail"
]


def fetch_url_lines(url: str, max_lines: int = 10000) -> List[str]:
    """Fetches text lines from a remote URL."""
    print(f"Fetching from {url} ...")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SentinelAI-ML-DatasetBuilder/1.0"}
    )
    lines = []
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if line and not line.startswith("#"):
                    lines.append(line)
                    if len(lines) >= max_lines:
                        break
    except Exception as e:
        print(f"Warning: Failed to fetch {url}: {e}")
    print(f"  Retrieved {len(lines)} lines from {url}")
    return lines


def download_phishing_urls(target_count: int = 4000) -> List[str]:
    """Retrieves verified active phishing URLs."""
    urls = []
    seen = set()

    for feed_url in PHISHING_FEED_URLS:
        lines = fetch_url_lines(feed_url, max_lines=target_count * 3)
        for u in lines:
            clean = u.strip()
            if len(clean) > 10 and clean.startswith(("http://", "https://", "ftp://")):
                if clean not in seen:
                    seen.add(clean)
                    urls.append(clean)
            if len(urls) >= target_count:
                break
        if len(urls) >= target_count:
            break

    random.seed(42)
    random.shuffle(urls)
    return urls[:target_count]


def download_benign_urls(target_count: int = 4000) -> List[str]:
    """
    Retrieves top benign domains from Majestic Million and generates
    realistic URLs with paths, subdomains, and legitimate query strings.
    """
    print(f"Fetching benign domains from Majestic Million: {MAJESTIC_MILLION_URL} ...")
    req = urllib.request.Request(
        MAJESTIC_MILLION_URL,
        headers={"User-Agent": "SentinelAI-ML-DatasetBuilder/1.0"}
    )

    domains = []
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            # Read first chunk of CSV
            text_stream = io.TextIOWrapper(resp, encoding="utf-8", errors="ignore")
            reader = csv.reader(text_stream)
            header = next(reader, None)
            for row in reader:
                if len(row) > 2 and row[2]:
                    dom = row[2].strip().lower()
                    if dom and "." in dom:
                        domains.append(dom)
                        if len(domains) >= target_count * 2:
                            break
    except Exception as e:
        print(f"Error fetching Majestic Million: {e}")

    print(f"  Retrieved {len(domains)} top domains from Majestic Million")

    # Curate benign URLs with diverse structures
    random.seed(42)
    random.shuffle(domains)

    benign_urls = []
    seen = set()

    for dom in domains:
        if len(benign_urls) >= target_count:
            break

        # Pick random structure
        mode = random.choices(["root", "subdomain", "path", "complex"], weights=[0.25, 0.25, 0.30, 0.20])[0]
        scheme = random.choices(["https://", "http://"], weights=[0.92, 0.08])[0]

        sub = ""
        path = ""

        if mode == "root":
            url = f"{scheme}{dom}/"
        elif mode == "subdomain":
            sub = random.choice([s for s in BENIGN_SUBDOMAINS if s])
            url = f"{scheme}{sub}.{dom}/"
        elif mode == "path":
            tpl = random.choice([p for p in BENIGN_PATH_TEMPLATES if p])
            path = tpl.format(
                rand_id=random.randint(10, 99999),
                rand_page=random.randint(1, 50),
                rand_year=random.choice([2023, 2024, 2025])
            )
            url = f"{scheme}{dom}{path}"
        else: # complex
            sub = random.choice([s for s in BENIGN_SUBDOMAINS if s])
            tpl = random.choice([p for p in BENIGN_PATH_TEMPLATES if p])
            path = tpl.format(
                rand_id=random.randint(10, 99999),
                rand_page=random.randint(1, 50),
                rand_year=random.choice([2023, 2024, 2025])
            )
            url = f"{scheme}{sub}.{dom}{path}"

        if url not in seen:
            seen.add(url)
            benign_urls.append(url)

    return benign_urls[:target_count]


def build_dataset(target_samples_per_class: int = 4000, force: bool = False) -> str:
    """Builds and caches the balanced dataset with domain groups."""
    os.makedirs(DATA_DIR, exist_ok=True)

    if os.path.exists(DATASET_CSV) and not force:
        with open(DATASET_CSV, "r", encoding="utf-8") as f:
            line_count = sum(1 for _ in f) - 1
        if line_count >= target_samples_per_class:
            print(f"Dataset already exists at {DATASET_CSV} with {line_count} samples. Use force=True to rebuild.")
            return DATASET_CSV

    print(f"\nBuilding new dataset: {target_samples_per_class} phishing + {target_samples_per_class} benign...")
    phishing_urls = download_phishing_urls(target_samples_per_class)
    benign_urls = download_benign_urls(target_samples_per_class)

    print(f"Collected: {len(phishing_urls)} phishing URLs, {len(benign_urls)} benign URLs.")

    rows = []
    print("Extracting domain groups and preparing CSV rows...")
    for u in phishing_urls:
        dg = extract_domain_group(u)
        rows.append({"url": u, "label": 1, "domain_group": dg, "type": "phishing"})

    for u in benign_urls:
        dg = extract_domain_group(u)
        rows.append({"url": u, "label": 0, "domain_group": dg, "type": "benign"})

    random.seed(42)
    random.shuffle(rows)

    with open(DATASET_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label", "domain_group", "type"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Successfully saved {len(rows)} samples to {DATASET_CSV}")

    # Write documentation about the dataset
    info_path = os.path.join(DATA_DIR, "DATASET_INFO.md")
    with open(info_path, "w", encoding="utf-8") as f:
        f.write(f"""# SentinelAI Training Dataset Documentation

## Overview
- **Total Samples:** {len(rows)}
- **Phishing Samples (label=1):** {len(phishing_urls)}
- **Benign Samples (label=0):** {len(benign_urls)}
- **Unique Domain Groups:** {len(set(r['domain_group'] for r in rows))}

## Sources
1. **Phishing URLs:**
   - [Phishing.Database Active Feed](https://github.com/mitchellkrogza/Phishing.Database)
   - [OpenPhish Public Community Feed](https://openphish.com)
2. **Benign URLs:**
   - [Majestic Million](https://majestic.com/reports/majestic-million) top ranked domains with realistic path, subdomain, and query parameter distribution to prevent root-domain path bias.

## Data Leakage Prevention
Every URL is tagged with its registered domain / eTLD+1 (`domain_group`).
Train/test splitting is performed strictly via `GroupShuffleSplit` and `GroupKFold` on `domain_group`, ensuring zero domain overlap between training and evaluation splits.
""")

    return DATASET_CSV


if __name__ == "__main__":
    force_build = "--force" in sys.argv
    build_dataset(target_samples_per_class=4000, force=force_build)
