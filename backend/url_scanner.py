"""
APKGuard AI — url_scanner.py
WhatsApp/SMS URL Scanner
Checks URLs against OpenPhish, extracts domain info, detects phishing patterns.
"""
import re
import os
import requests
import logging
from urllib.parse import urlparse
from datetime import datetime

log = logging.getLogger("apkguard.urlscanner")

SUSPICIOUS_PATTERNS = [
    (r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', "IP address used instead of domain"),
    (r'(free|winner|won|prize|claim|urgent|verify|suspend|block|limited)', "Urgency/prize language"),
    (r'(paypal|amazon|google|apple|microsoft|bank|boi|sbi|hdfc|icici).+\.(tk|ml|ga|cf|gq|xyz|top|click|link)', "Brand impersonation with suspicious TLD"),
    # URL shortener detection handled by unshorten_url function
    (r'(login|signin|verify|update|confirm|secure|account).+\.(tk|ml|ga|cf|gq|xyz)', "Fake login page pattern"),
    (r'https?://[^/]*\d{5,}', "Suspicious numeric subdomain"),
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link', '.work', '.loan']

def extract_urls(text: str) -> list:
    """Extract all URLs from a text message."""
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)


SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','rb.gy','cutt.ly','short.io','tiny.cc','is.gd','buff.ly']

def unshorten_url(url: str) -> tuple:
    """Follow redirects to get the final URL. Returns (final_url, was_shortened)."""
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower().replace("www.","")
        is_shortener = any(s in domain for s in SHORTENERS)
        if not is_shortener:
            return url, False
        # Mark as shortener even if we can't resolve
        try:
            resp = requests.head(url, allow_redirects=True, timeout=8,
                headers={"User-Agent": "Mozilla/5.0"})
            final = resp.url
            if final and final != url:
                log.info(f"URL unshortened: {url} -> {final}")
                return final, True
        except:
            pass
        # Could not resolve but it IS a shortener — flag as suspicious
        return url, True
    except Exception as e:
        log.warning(f"Unshorten error {url}: {e}")
    return url, False

def check_openphish(url: str) -> bool:
    """Check URL against OpenPhish feed."""
    try:
        resp = requests.get(
            "https://openphish.com/feed.txt",
            timeout=10,
            headers={"User-Agent": "APKGuard-AI-Research/1.0"}
        )
        if resp.status_code == 200:
            feed = resp.text.lower()
            return url.lower().rstrip("/") in feed
    except:
        pass
    return False

def analyze_url(url: str) -> dict:
    """Analyze a single URL for threats."""
    result = {
        "url": url,
        "domain": "",
        "risk_level": "safe",
        "risk_score": 0,
        "threats": [],
        "in_openphish": False,
        "suspicious_patterns": [],
        "tld": "",
        "timestamp": datetime.utcnow().isoformat()
    }

    # Unshorten URL if needed
    original_url = url
    url, was_shortened = unshorten_url(url)
    if was_shortened:
        result["original_url"] = original_url
        result["unshortened_to"] = url
        if url != original_url:
            result["suspicious_patterns"].append(f"Shortener resolves to: {url}")
        else:
            result["suspicious_patterns"].append("URL shortener — destination hidden, could not resolve")
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        result["domain"] = domain
        result["tld"] = tld
    except:
        result["threats"].append("Invalid URL format")
        result["risk_level"] = "suspicious"
        result["risk_score"] = 40
        return result

    # Check OpenPhish
    if check_openphish(url):
        result["in_openphish"] = True
        result["threats"].append("URL found in OpenPhish database")
        result["risk_score"] += 80

    # Check suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        result["suspicious_patterns"].append(f"Suspicious TLD: {tld}")
        result["risk_score"] += 30

    # Check patterns
    for pattern, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            result["suspicious_patterns"].append(description)
            result["risk_score"] += 20

    # Cap score at 100
    result["risk_score"] = min(result["risk_score"], 100)

    # Determine risk level
    if result["risk_score"] >= 70 or result["in_openphish"]:
        result["risk_level"] = "malicious"
    elif result["risk_score"] >= 30:
        result["risk_level"] = "suspicious"
    else:
        result["risk_level"] = "safe"

    return result

def scan_message(message: str) -> dict:
    """Scan a WhatsApp/SMS message for malicious URLs."""
    urls = extract_urls(message)

    if not urls:
        return {
            "message_scanned": True,
            "urls_found": 0,
            "urls": [],
            "overall_risk": "safe",
            "summary": "No URLs found in message"
        }

    results = [analyze_url(url) for url in urls]
    
    max_score = max(r["risk_score"] for r in results)
    overall_risk = "malicious" if max_score >= 70 else "suspicious" if max_score >= 30 else "safe"

    return {
        "message_scanned": True,
        "urls_found": len(urls),
        "urls": results,
        "overall_risk": overall_risk,
        "max_risk_score": max_score,
        "summary": f"Found {len(urls)} URL(s). Risk: {overall_risk.upper()}"
    }
