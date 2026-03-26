"""
threat_intel.py
===============
Live Threat Intelligence Feed Manager

Downloads and caches threat feeds from:
  - OpenPhish  (phishing URLs, updated every 6h)
  - URLhaus     (malicious URLs, updated every 6h)

Provides O(1) URL lookup against cached sets.
No API key required for these feeds.
Optional: VirusTotal, Google Safe Browsing, AbuseIPDB (env vars).
"""

import os
import time
import hashlib
import re
import requests
from urllib.parse import urlparse
from typing import Tuple, Optional

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

_BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
FEEDS_DIR   = os.path.join(_BASE_DIR, 'data', 'feeds')
REFRESH_H   = 6          # refresh feeds every N hours
TIMEOUT_S   = 12         # HTTP timeout for feed downloads

FEED_URLS = {
    'openphish': 'https://openphish.com/feed.txt',
    'urlhaus':   'https://urlhaus.abuse.ch/downloads/text/',
}

# In-memory lookup structures, populated at startup and on refresh
_url_exact: set  = set()   # full normalised URLs
_url_domain: set = set()   # domains extracted from feed URLs
_feed_loaded = False
_last_refresh = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_stale(path: str) -> bool:
    if not os.path.exists(path):
        return True
    age_h = (time.time() - os.path.getmtime(path)) / 3600
    return age_h > REFRESH_H


def _normalise_url(url: str) -> str:
    """Lowercase, strip scheme, trailing slash and fragment."""
    url = url.lower().strip().rstrip('/')
    if '#' in url:
        url = url[:url.index('#')]
    return re.sub(r'^https?://', '', url)


def _domain_from_url(url: str) -> str:
    try:
        return urlparse(url if '://' in url else 'http://' + url).netloc.lower()
    except Exception:
        return ''


def _download(name: str, feed_url: str, dest: str) -> bool:
    try:
        r = requests.get(
            feed_url, timeout=TIMEOUT_S,
            headers={'User-Agent': 'EmailThreatDetector/2.0 (security research)'},
        )
        if r.ok and len(r.text) > 100:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(r.text)
            return True
        print(f"[ThreatIntel] Feed {name} returned HTTP {r.status_code}")
    except Exception as e:
        print(f"[ThreatIntel] Feed download failed ({name}): {e}")
    return False


def _parse_feed(path: str) -> Tuple[set, set]:
    """Return (url_set, domain_set) from a cached feed file."""
    urls, domains = set(), set()
    if not os.path.exists(path):
        return urls, domains
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # URLhaus lines: <url>  (tab-separated entries — take first field)
            url = line.split('\t')[0].strip()
            if not url.startswith(('http://', 'https://')):
                continue
            norm = _normalise_url(url)
            urls.add(norm)
            d = _domain_from_url(norm)
            if d:
                domains.add(d)
    return urls, domains


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def refresh_feeds(force: bool = False) -> None:
    """Download stale feeds and rebuild in-memory lookup sets."""
    global _url_exact, _url_domain, _feed_loaded, _last_refresh

    os.makedirs(FEEDS_DIR, exist_ok=True)
    combined_urls, combined_domains = set(), set()

    for name, feed_url in FEED_URLS.items():
        dest = os.path.join(FEEDS_DIR, f'{name}.txt')
        if force or _is_stale(dest):
            ok = _download(name, feed_url, dest)
            status = 'updated' if ok else 'using cached'
        else:
            status = 'cached'
        u, d = _parse_feed(dest)
        combined_urls   |= u
        combined_domains |= d
        print(f"[ThreatIntel] {name}: {len(u):,} URLs ({status})")

    _url_exact   = combined_urls
    _url_domain  = combined_domains
    _feed_loaded = True
    _last_refresh = time.time()
    print(f"[ThreatIntel] Total: {len(_url_exact):,} malicious URLs, "
          f"{len(_url_domain):,} malicious domains loaded")


def _ensure_loaded() -> None:
    global _feed_loaded
    if not _feed_loaded or (time.time() - _last_refresh) > REFRESH_H * 3600:
        refresh_feeds()


def check_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Check a URL against all loaded threat feeds.
    Returns (is_threat, feed_name_or_None).
    """
    _ensure_loaded()
    if not url:
        return False, None

    norm = _normalise_url(url)
    domain = _domain_from_url(norm)

    # 1. Exact URL match (scheme stripped natively by normalise_url)
    if norm in _url_exact:
        return True, 'FEED_EXACT_MATCH'

    # 2. Path chopping: check if any parent path is flagged (O(P) instead of O(N))
    # E.g., for evil.com/a/b/c, checks evil.com/a/b, evil.com/a
    parts = norm.split('/')
    for i in range(len(parts) - 1, 0, -1):
        parent_path = '/'.join(parts[:i])
        if parent_path in _url_exact:
            return True, 'FEED_URL_MATCH'

    # 3. Domain-only match (the whole domain is known bad)
    if domain and domain in _url_domain:
        return True, 'FEED_DOMAIN_MATCH'

    return False, None


def check_urls_batch(urls: list) -> Tuple[bool, Optional[str], list]:
    """
    Check a list of URLs. Returns (any_threat, first_source, list_of_flagged).
    """
    _ensure_loaded()
    flagged = []
    first_src = None
    for url in urls:
        hit, src = check_url(url)
        if hit:
            flagged.append(url)
            if first_src is None:
                first_src = src
    return bool(flagged), first_src, flagged


# ──────────────────────────────────────────────────────────────────────────────
# Optional live API checks (keys from environment)
# ──────────────────────────────────────────────────────────────────────────────

def virustotal_check_url(url: str) -> Tuple[bool, str]:
    """
    Query VirusTotal URL lookup. Requires VIRUSTOTAL_API_KEY env var.
    Returns (is_malicious, verdict_string).
    """
    api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return False, 'NO_KEY'
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        r = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': api_key},
            timeout=5,
        )
        if r.ok:
            stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            if malicious >= 2 or suspicious >= 3:
                return True, f'VIRUSTOTAL: {malicious} malicious/{suspicious} suspicious engines'
    except Exception:
        pass
    return False, 'CLEAN'


def gsb_check_urls(urls: list) -> Tuple[bool, list]:
    """
    Query Google Safe Browsing. Requires GOOGLE_SAFE_BROWSING_KEY env var.
    Returns (any_threat, list_of_flagged_urls).
    """
    api_key = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')
    if not api_key or not urls:
        return False, []
    try:
        payload = {
            'client': {'clientId': 'email-threat-detector', 'clientVersion': '2.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                                'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': u} for u in urls[:100]],
            },
        }
        r = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
            json=payload, timeout=5,
        )
        if r.ok:
            matches = r.json().get('matches', [])
            flagged = [m['threat']['url'] for m in matches]
            return bool(flagged), flagged
    except Exception:
        pass
    return False, []


def abuseipdb_check(ip: str) -> Tuple[bool, int]:
    """
    Query AbuseIPDB reputation. Requires ABUSEIPDB_KEY env var.
    Returns (is_abusive, abuse_confidence_score 0-100).
    """
    api_key = os.environ.get('ABUSEIPDB_KEY', '')
    if not api_key or not ip:
        return False, 0
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            headers={'Key': api_key, 'Accept': 'application/json'},
            timeout=5,
        )
        if r.ok:
            score = r.json().get('data', {}).get('abuseConfidenceScore', 0)
            return score >= 50, score
    except Exception:
        pass
    return False, 0
