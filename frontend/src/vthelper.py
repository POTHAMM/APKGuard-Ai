"""
VirusTotal helper — add this to ~/apkguard/backend/analyzer.py
Also add VT_API_KEY=your_key to ~/apkguard/backend/.env
"""
import hashlib, requests, os

def get_virustotal_result(apk_path: str) -> dict:
    api_key = os.getenv("9397974fbc65bd30f51470a6bc8977bf078496dba5338ed3b51a3f339102dd96", "")
    sha256 = hashlib.sha256(open(apk_path, "rb").read()).hexdigest()
    if not api_key:
        return {"sha256": sha256, "detected": 0, "total": 0, "error": "No VT_API_KEY"}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key}, timeout=10
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "sha256": sha256,
                "detected": stats.get("malicious", 0) + stats.get("suspicious", 0),
                "total": sum(stats.values()),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }
        return {"sha256": sha256, "detected": 0, "total": 0, "not_found": r.status_code == 404}
    except Exception as e:
        return {"sha256": sha256, "detected": 0, "total": 0, "error": str(e)}
