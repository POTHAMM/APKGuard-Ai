"""
APKGuard AI — threat_feeds.py
Real-time threat intelligence from MalwareBazaar + OpenPhish
"""
import requests
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

CACHE_FILE = Path("/tmp/apkguard_threat_cache.json")
CACHE_TTL = 3600  # 1 hour

HEADERS = {"User-Agent": "APKGuard-AI-Research/1.0", "Content-Type": "application/x-www-form-urlencoded"}

# ── Cache helpers ─────────────────────────────────────────────────────────────

def _load_cache():
    try:
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text())
            if time.time() - data.get("ts", 0) < CACHE_TTL:
                return data
    except:
        pass
    return None

def _save_cache(data: dict):
    data["ts"] = time.time()
    CACHE_FILE.write_text(json.dumps(data))

# ── MalwareBazaar ─────────────────────────────────────────────────────────────

def fetch_otx_android_iocs(limit=10) -> list:
    """Fetch Android malware IOCs from AlienVault OTX public API (no auth required)."""
    try:
        resp = requests.get(
            "https://otx.alienvault.com/otxapi/pulses/?limit=20&q=android+malware",
            headers={"User-Agent": "APKGuard-AI-Research/1.0"},
            timeout=15
        )
        if resp.status_code == 200:
            pulses = resp.json().get("results", [])
            results = []
            for p in pulses[:limit]:
                results.append({
                    "sha256": "",
                    "filename": p.get("name", "Unknown"),
                    "family": p.get("name", "Android Malware"),
                    "tags": p.get("tags") or [],
                    "first_seen": p.get("created", ""),
                    "source": "AlienVault OTX",
                    "pulse_id": p.get("id", "")
                })
            return results
    except Exception as e:
        print(f"[OTX] Error: {e}")
    return []

def fetch_malwarebazaar_recent(limit=10) -> list:
    """Use AlienVault OTX as the malware feed (MalwareBazaar requires auth)."""
    return fetch_otx_android_iocs(limit)

def check_hash_malwarebazaar(sha256: str) -> dict:
    """Check a specific SHA256 against MalwareBazaar."""
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            headers=HEADERS, timeout=15
        )
        data = resp.json()
        if data.get("query_status") == "ok":
            s = data["data"][0]
            return {
                "found": True,
                "family": s.get("signature") or "Unknown",
                "tags": s.get("tags") or [],
                "first_seen": s.get("first_seen", ""),
                "reporter": s.get("reporter", ""),
                "source": "MalwareBazaar"
            }
    except Exception as e:
        print(f"[MalwareBazaar hash check] Error: {e}")
    return {"found": False}

# ── OpenPhish ─────────────────────────────────────────────────────────────────

def fetch_openphish_urls(limit=50) -> list:
    """Fetch active phishing URLs from OpenPhish."""
    try:
        resp = requests.get(
            "https://openphish.com/feed.txt",
            timeout=15,
            headers={"User-Agent": "APKGuard-AI-Research/1.0"}
        )
        if resp.status_code == 200:
            urls = [u.strip() for u in resp.text.splitlines() if u.strip()]
            return urls[:limit]
    except Exception as e:
        print(f"[OpenPhish] Error: {e}")
    return []

def check_url_openphish(url: str, phish_list: list) -> bool:
    """Check if a URL matches any known phishing URL."""
    url_lower = url.lower().rstrip("/")
    for phish in phish_list:
        phish_lower = phish.lower().rstrip("/")
        if url_lower == phish_lower or url_lower.startswith(phish_lower):
            return True
    return False

def check_domain_openphish(domain: str, phish_list: list) -> list:
    """Find all phishing URLs from a specific domain."""
    domain_lower = domain.lower()
    return [u for u in phish_list if domain_lower in u.lower()]

# ── Combined feed ─────────────────────────────────────────────────────────────

def get_threat_feeds(force_refresh=False) -> dict:
    """Get combined threat intel, with caching."""
    if not force_refresh:
        cached = _load_cache()
        if cached:
            return cached

    print("[ThreatFeeds] Refreshing from MalwareBazaar + OpenPhish...")
    feeds = {
        "malwarebazaar": fetch_malwarebazaar_recent(10),
        "urlhaus": fetch_urlhaus_recent(10),
        "openphish": fetch_openphish_urls(100),
        "last_updated": datetime.utcnow().isoformat(),
        "status": "ok"
    }
    _save_cache(feeds)
    return feeds

def scan_apk_against_feeds(sha256: str, urls_in_apk: list = []) -> dict:
    """
    Cross-reference APK sha256 and embedded URLs against threat feeds.
    Returns threat intel enrichment dict.
    """
    result = {
        "hash_match": None,
        "phishing_urls": [],
        "threat_level": "clean",
        "intel_source": []
    }

    # Check hash
    hash_result = check_hash_malwarebazaar(sha256)
    if hash_result.get("found"):
        result["hash_match"] = hash_result
        result["threat_level"] = "malicious"
        result["intel_source"].append("MalwareBazaar")

    # Check URLs from APK against OpenPhish
    if urls_in_apk:
        feeds = get_threat_feeds()
        phish_list = feeds.get("openphish", [])
        for url in urls_in_apk:
            if check_url_openphish(url, phish_list):
                result["phishing_urls"].append(url)
                result["intel_source"].append("OpenPhish")
                if result["threat_level"] == "clean":
                    result["threat_level"] = "suspicious"

    if result["intel_source"]:
        result["intel_source"] = list(set(result["intel_source"]))

    return result

if __name__ == "__main__":
    print("=== APKGuard Threat Feeds Test ===\n")
    print("[1] Fetching MalwareBazaar recent APKs...")
    mb = fetch_malwarebazaar_recent(5)
    for s in mb:
        print(f"  {s['filename']:40} {s['family']}")

    print("\n[2] Fetching OpenPhish URLs...")
    urls = fetch_openphish_urls(5)
    for u in urls:
        print(f"  {u}")

    print("\n[Done]")
