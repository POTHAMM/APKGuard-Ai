import os
import re
import hashlib
import zipfile
import requests
from pathlib import Path
from androguard.misc import AnalyzeAPK
from behavioral import analyze_behavior
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS":                   {"score": 10, "reason": "Can read SMS including OTPs"},
    "android.permission.RECEIVE_SMS":                {"score": 10, "reason": "Intercepts incoming SMS silently"},
    "android.permission.SEND_SMS":                   {"score": 8,  "reason": "Can send SMS without user knowledge"},
    "android.permission.READ_CALL_LOG":              {"score": 7,  "reason": "Accesses full call history"},
    "android.permission.PROCESS_OUTGOING_CALLS":     {"score": 7,  "reason": "Can intercept and redirect calls"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"score": 15, "reason": "Can control screen and steal passwords"},
    "android.permission.SYSTEM_ALERT_WINDOW":        {"score": 12, "reason": "Can overlay fake screens on banking apps"},
    "android.permission.REQUEST_INSTALL_PACKAGES":   {"score": 9,  "reason": "Can silently install malicious APKs"},
    "android.permission.READ_CONTACTS":              {"score": 5,  "reason": "Exfiltrates contact list"},
    "android.permission.RECORD_AUDIO":               {"score": 8,  "reason": "Can record microphone secretly"},
    "android.permission.CAMERA":                     {"score": 6,  "reason": "Can capture photos secretly"},
    "android.permission.READ_PHONE_STATE":           {"score": 6,  "reason": "Reads IMEI and device identifiers"},
    "android.permission.WRITE_EXTERNAL_STORAGE":     {"score": 4,  "reason": "Can write and steal files"},
    "android.permission.GET_ACCOUNTS":               {"score": 6,  "reason": "Enumerates Google and banking accounts"},
    "android.permission.DISABLE_KEYGUARD":           {"score": 8,  "reason": "Can unlock screen programmatically"},
    "android.permission.RECEIVE_BOOT_COMPLETED":     {"score": 5,  "reason": "Runs automatically on device boot"},
}

SUSPICIOUS_APIS = {
    "sendTextMessage":                 {"score": 8,  "reason": "Sends SMS programmatically"},
    "getDeviceId":                     {"score": 6,  "reason": "Harvests IMEI device identifier"},
    "getSubscriberId":                 {"score": 6,  "reason": "Harvests SIM card IMSI number"},
    "getLine1Number":                  {"score": 6,  "reason": "Reads phone number"},
    "DexClassLoader":                  {"score": 10, "reason": "Loads external code dynamically"},
    "PathClassLoader":                 {"score": 7,  "reason": "Dynamic class loading detected"},
    "Runtime.exec":                    {"score": 9,  "reason": "Executes shell commands on device"},
    "execShellCommand":                {"score": 9,  "reason": "Direct shell command execution"},
    "setOnAccessibilityEventListener": {"score": 10, "reason": "Abuses accessibility to monitor screen"},
    "onAccessibilityEvent":            {"score": 10, "reason": "Reads screen content via accessibility"},
    "getPassword":                     {"score": 8,  "reason": "Attempts to extract stored passwords"},
    "HttpURLConnection":               {"score": 3,  "reason": "Network communication detected"},
    "Cipher.getInstance":              {"score": 4,  "reason": "Cryptographic operations detected"},
    "Base64.decode":                   {"score": 3,  "reason": "Base64 decoding detected"},
    "Class.forName":                   {"score": 6,  "reason": "Java reflection detected"},
    "Method.invoke":                   {"score": 6,  "reason": "Reflection invocation detected"},
    "TelephonyManager":                {"score": 5,  "reason": "Accesses telephony data"},
}

BANKING_INDICATORS = [
    "overlay", "inject", "keylog", "bankbot",
    "credential", "phish", "intercept", "hidden",
    "invisible", "stealth", "hook", "capture_screen",
]
def compute_hashes(apk_path):
    h_md5    = hashlib.md5()
    h_sha1   = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {
        "md5":     h_md5.hexdigest(),
        "sha1":    h_sha1.hexdigest(),
        "sha256":  h_sha256.hexdigest(),
        "size_kb": round(os.path.getsize(apk_path) / 1024, 2),
    }


def check_virustotal(sha256: str) -> dict:
    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "No VT API key configured"}
    try:
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            undetected  = stats.get("undetected", 0)
            total       = malicious + suspicious + undetected + stats.get("harmless", 0)
            return {
                "available":   True,
                "detected":    malicious + suspicious,
                "malicious":   malicious,
                "suspicious":  suspicious,
                "undetected":  undetected,
                "total":       total,
                "sha256":      sha256,
                "permalink":   f"https://www.virustotal.com/gui/file/{sha256}",
            }
        elif r.status_code == 404:
            return {"available": True, "detected": 0, "total": 0, "not_found": True, "sha256": sha256}
        else:
            return {"available": False, "reason": f"VT API error: {r.status_code}"}
    except Exception as e:
        return {"available": False, "reason": str(e)[:100]}


def extract_urls_and_ips(apk_path):
    urls, ips = set(), set()
    url_re = re.compile(r'https?://[^\s\'"<>]{4,}')
    ip_re  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    whitelist = ["google.com", "gstatic.com", "googleapis.com",
                 "android.com", "w3.org", "apache.org", "firebase.com"]
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                if name.endswith(('.dex','.xml','.json','.js','.html','.txt')):
                    try:
                        content = z.read(name).decode('utf-8', errors='ignore')
                        for url in url_re.findall(content):
                            if not any(w in url for w in whitelist):
                                urls.add(url[:120])
                        for ip in ip_re.findall(content):
                            if not ip.startswith(('127.','0.0.','255.')):
                                ips.add(ip)
                    except Exception:
                        pass
    except Exception:
        pass
    return {"urls": list(urls)[:20], "ips": list(ips)[:10]}


def detect_obfuscation(dx):
    indicators = []
    score = 0
    try:
        classes = [c.name for c in dx.get_classes()]
        short   = [c for c in classes if len(c.split('/')[-1].replace(';','')) <= 2]
        ratio   = len(short) / max(len(classes), 1)
        if ratio > 0.3:
            indicators.append("Heavy class name obfuscation ({}%)".format(int(ratio*100)))
            score += 10
        elif ratio > 0.1:
            indicators.append("Moderate class name obfuscation")
            score += 5
    except Exception as e:
        indicators.append(f"Obfuscation check partial: {str(e)[:50]}")
    return {"detected": len(indicators) > 0, "score": score, "indicators": indicators}


def detect_native_libs(apk_path):
    libs = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            libs = [n for n in z.namelist() if n.startswith('lib/') and n.endswith('.so')]
    except Exception:
        pass
    return libs
def analyze_apk(apk_path):
    results = {
        "status": "success",
        "file_info": {},
        "app_info": {},
        "permissions": {"dangerous": [], "all": []},
        "suspicious_apis": [],
        "urls_ips": {"urls": [], "ips": []},
        "obfuscation": {},
        "native_libs": [],
        "banking_indicators": [],
        "virustotal": {},
        "errors": [],
    }

    try:
        results["file_info"] = compute_hashes(apk_path)
        results["file_info"]["filename"] = Path(apk_path).name
    except Exception as e:
        results["errors"].append(f"Hash failed: {e}")

    # ── VirusTotal lookup ──
    try:
        sha256 = results["file_info"].get("sha256", "")
        if sha256:
            print(f"Checking VirusTotal for {sha256[:16]}...")
            results["virustotal"] = check_virustotal(sha256)
    except Exception as e:
        results["virustotal"] = {"available": False, "reason": str(e)}

    try:
        a, d, dx = AnalyzeAPK(apk_path)
        results["app_info"] = {
            "package":       a.get_package(),
            "app_name":      str(a.get_app_name()),
            "version_name":  str(a.get_androidversion_name()),
            "version_code":  str(a.get_androidversion_code()),
            "min_sdk":       str(a.get_min_sdk_version()),
            "target_sdk":    str(a.get_target_sdk_version()),
            "main_activity": str(a.get_main_activity()),
        }
        all_perms = a.get_permissions()
        results["permissions"]["all"] = all_perms
        for perm in all_perms:
            if perm in DANGEROUS_PERMISSIONS:
                results["permissions"]["dangerous"].append({
                    "permission": perm,
                    "score":      DANGEROUS_PERMISSIONS[perm]["score"],
                    "reason":     DANGEROUS_PERMISSIONS[perm]["reason"],
                })
        found_apis = set()
        for cls in dx.get_classes():
            for method in cls.get_methods():
                try:
                    for _, call, _ in method.get_xref_to():
                        mname = call.name
                        for api, info in SUSPICIOUS_APIS.items():
                            if api in mname and api not in found_apis:
                                found_apis.add(api)
                                results["suspicious_apis"].append({
                                    "api":    api,
                                    "score":  info["score"],
                                    "reason": info["reason"],
                                })
                except Exception:
                    pass
        results["obfuscation"] = detect_obfuscation(dx)
        found_bi = []
        for cls in dx.get_classes():
            cname = cls.name.lower()
            for indicator in BANKING_INDICATORS:
                if indicator in cname and indicator not in found_bi:
                    found_bi.append(indicator)
        results["banking_indicators"] = found_bi
    except Exception as e:
        results["errors"].append(f"Androguard failed: {str(e)[:200]}")
        results["status"] = "partial"

    try:
        results["urls_ips"] = extract_urls_and_ips(apk_path)
    except Exception as e:
        results["errors"].append(f"URL extraction failed: {e}")

    try:
        results["native_libs"] = detect_native_libs(apk_path)
    except Exception as e:
        results["errors"].append(f"Native lib detection failed: {e}")

    try:
        results["behavioral_analysis"] = analyze_behavior(apk_path, analysis=results)
    except Exception as e:
        results["behavioral_analysis"] = {"error": str(e)}

    return results
