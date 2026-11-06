"""
SentinelAI Phishing & Scam Link Shield
Canonical Python Feature Extractor

Extracts the exact 14-dimensional feature vector matching ml/canonical_schema.json
and ensures 100% mathematical parity with the client-side JavaScript extractor.
"""

import json
import math
import os
import re
import urllib.parse
from collections import Counter
from typing import Dict, List, Optional, Tuple, Union
import tldextract

# Load schema definitions if available, otherwise use hardcoded canonical constants
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "canonical_schema.json")
if os.path.exists(SCHEMA_PATH):
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        _schema = json.load(f)
    FEATURE_NAMES = [feat["name"] for feat in _schema["features"]]
    SUSPICIOUS_TLDS = set(_schema["suspicious_tlds"])
    SUSPICIOUS_KEYWORDS = _schema["suspicious_keywords"]
else:
    FEATURE_NAMES = [
        "url_length",
        "domain_length",
        "num_dots",
        "has_ip",
        "has_at_symbol",
        "num_hyphens",
        "num_subdomains",
        "is_https",
        "has_double_slash_in_path",
        "num_suspicious_keywords",
        "has_suspicious_tld",
        "num_query_params",
        "special_char_count",
        "domain_entropy"
    ]
    SUSPICIOUS_TLDS = {
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz",
        "fit", "work", "icu", "loan", "click", "country", "kim",
        "science", "monster", "quest", "live", "cam", "rest",
        "gdn", "stream", "party", "trade", "bid", "men", "surf",
        "zip", "mov"
    }
    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "verify", "verification", "update",
        "banking", "secure", "account", "confirm", "password",
        "credential", "auth", "recover", "wallet", "security",
        "billing", "invoice", "appleid", "paypal", "metamask"
    ]

# Regex patterns matching JavaScript
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
IPV6_REGEX = re.compile(r"^\[?[a-fA-F0-9:]+\]?$")
SPECIAL_CHARS_REGEX = re.compile(r"[%&=?_~]")


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string rounded to 3 decimal places."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 3)


def check_is_ip(hostname: str) -> int:
    """Returns 1 if hostname is a raw IPv4 or IPv6 address, else 0."""
    if not hostname:
        return 0
    clean_host = hostname.strip("[]")
    if IPV4_REGEX.match(clean_host):
        return 1
    if ":" in clean_host and IPV6_REGEX.match(clean_host):
        return 1
    return 0


def parse_url_components(raw_url: str) -> Tuple[str, str, str, str, str]:
    """
    Parses a URL into normalized (scheme, hostname, pathname, query, full_url).
    Ensures missing schemes default to http for parsing.
    """
    clean_url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        clean_url = "http://" + clean_url

    parsed = urllib.parse.urlparse(clean_url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    pathname = parsed.path or ""
    query = parsed.query or ""
    full_url = clean_url.lower()

    return scheme, hostname, pathname, query, full_url


def extract_features(raw_url: str) -> List[Union[int, float]]:
    """
    Extracts the canonical 14 features in exact index order:
      [0] url_length
      [1] domain_length
      [2] num_dots
      [3] has_ip
      [4] has_at_symbol
      [5] num_hyphens
      [6] num_subdomains
      [7] is_https
      [8] has_double_slash_in_path
      [9] num_suspicious_keywords
      [10] has_suspicious_tld
      [11] num_query_params
      [12] special_char_count
      [13] domain_entropy
    """
    scheme, hostname, pathname, query, full_url = parse_url_components(raw_url)

    # 0. url_length
    url_length = len(full_url)

    # 1. domain_length
    domain_length = len(hostname)

    # 2. num_dots in hostname
    num_dots = hostname.count(".")

    # 3. has_ip
    has_ip = check_is_ip(hostname)

    # 4. has_at_symbol
    has_at_symbol = 1 if "@" in full_url else 0

    # 5. num_hyphens in hostname
    num_hyphens = hostname.count("-")

    # 6. num_subdomains
    parts = [p for p in hostname.split(".") if p]
    if has_ip == 1:
        num_subdomains = 0
    elif len(parts) > 2:
        num_subdomains = len(parts) - 2
    else:
        num_subdomains = 0

    # 7. is_https
    is_https = 1 if scheme == "https" else 0

    # 8. has_double_slash_in_path
    has_double_slash_in_path = 1 if "//" in pathname else 0

    # 9. num_suspicious_keywords
    target_string = (pathname + "?" + query).lower()
    num_suspicious_keywords = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in target_string)

    # 10. has_suspicious_tld
    tld = parts[-1] if parts else ""
    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # 11. num_query_params
    if query:
        query_parts = [qp for qp in query.split("&") if qp]
        num_query_params = len(query_parts)
    else:
        num_query_params = 0

    # 12. special_char_count
    special_char_count = len(SPECIAL_CHARS_REGEX.findall(full_url))

    # 13. domain_entropy
    domain_entropy = calculate_entropy(hostname)

    return [
        url_length,
        domain_length,
        num_dots,
        has_ip,
        has_at_symbol,
        num_hyphens,
        num_subdomains,
        is_https,
        has_double_slash_in_path,
        num_suspicious_keywords,
        has_suspicious_tld,
        num_query_params,
        special_char_count,
        domain_entropy
    ]


def extract_features_dict(raw_url: str) -> Dict[str, Union[int, float]]:
    """Returns features as a dictionary mapped by canonical feature name."""
    vec = extract_features(raw_url)
    return {name: val for name, val in zip(FEATURE_NAMES, vec)}


_tld_extractor = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=())

def extract_domain_group(raw_url: str) -> str:
    """
    Extracts the registered domain / eTLD+1 for domain-level grouping.
    Prevents data leakage by ensuring all subdomains and paths of a domain
    stay grouped together in either train or test, never split across both.
    If the hostname is a raw IP address or invalid domain, the hostname itself is returned.
    """
    _, hostname, _, _, _ = parse_url_components(raw_url)
    if not hostname:
        return "unknown"
    if check_is_ip(hostname):
        return hostname

    extracted = _tld_extractor(hostname)
    reg_domain = getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain
    if reg_domain:
        return reg_domain.lower()
    return hostname.lower()
