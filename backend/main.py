import os, json, hashlib, tempfile, logging
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from dotenv import load_dotenv
from ai_engine import get_ai_analysis

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(message)s")
log = logging.getLogger("apkguard")

from analyzer import analyze_apk
from scorer import calculate_score, calculate_final_score, calculate_dynamic_score

try:
    from smali_deobfuscator import run_smali_deobfuscation
    SMALI_AVAILABLE = True
except ImportError:
    SMALI_AVAILABLE = False

try:
    from ml_classifier import kmeans_classify
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from ai_engine import get_ai_analysis
from behavioral import analyze_behavior

try:
    from siem_webhook import send_siem_alert
    SIEM_AVAILABLE = True
except ImportError:
    SIEM_AVAILABLE = False

try:
    from threat_feeds import get_threat_feeds, scan_apk_against_feeds
    THREAT_FEEDS_AVAILABLE = True
except ImportError:
    THREAT_FEEDS_AVAILABLE = False

try:
    from dynamic_analyzer import run_dynamic_analysis
    DYNAMIC_AVAILABLE = True
except ImportError:
    DYNAMIC_AVAILABLE = False

app = FastAPI(title="APKGuard AI", version="2.0.0")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

HISTORY_FILE = Path(os.path.expanduser("~/apkguard/scan_history.json"))
CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)

def get_apk_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

def load_cached_result(sha256: str) -> dict | None:
    cache_path = CACHE_DIR / f"{sha256}.json"
    if cache_path.exists():
        with open(cache_path, "r") as f:
            return json.load(f)
    return None

def save_result_to_cache(sha256: str, result: dict) -> None:
    cache_path = CACHE_DIR / f"{sha256}.json"
    with open(cache_path, "w") as f:
        json.dump(result, f, indent=2)

def load_history():
    try:
        if HISTORY_FILE.exists():
            return json.loads(HISTORY_FILE.read_text())
    except:
        pass
    return []

def save_history(history):
    try:
        HISTORY_FILE.write_text(json.dumps(history[-50:], indent=2))
    except Exception as e:
        log.warning(f"Could not save history: {e}")

scan_history = load_history()

def get_virustotal_result(apk_path):
    import requests as req, time
    api_key = os.getenv("VT_API_KEY", "")
    sha256 = hashlib.sha256(open(apk_path, "rb").read()).hexdigest()
    if not api_key:
        return {"sha256": sha256, "detected": 0, "total": 0, "error": "No VT_API_KEY"}
    headers = {"x-apikey": api_key}
    try:
        r = req.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers, timeout=12)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"sha256": sha256,
                "detected": stats.get("malicious",0) + stats.get("suspicious",0),
                "total": sum(stats.values()),
                "malicious": stats.get("malicious",0),
                "suspicious": stats.get("suspicious",0)}
        if r.status_code == 404:
            log.info("VT: hash not found, uploading file...")
            with open(apk_path, "rb") as f:
                upload_r = req.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers={"x-apikey": api_key},
                    files={"file": (os.path.basename(apk_path), f, "application/vnd.android.package-archive")},
                    timeout=60
                )
            if upload_r.status_code == 200:
                analysis_id = upload_r.json().get("data", {}).get("id", "")
                log.info(f"VT: uploaded, analysis_id={analysis_id}, waiting...")
                for _ in range(6):
                    time.sleep(5)
                    poll_r = req.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers, timeout=12
                    )
                    if poll_r.status_code == 200:
                        poll_data = poll_r.json()
                        status = poll_data.get("data", {}).get("attributes", {}).get("status", "")
                        if status == "completed":
                            stats = poll_data["data"]["attributes"]["stats"]
                            return {"sha256": sha256,
                                "detected": stats.get("malicious",0) + stats.get("suspicious",0),
                                "total": sum(stats.values()),
                                "malicious": stats.get("malicious",0),
                                "suspicious": stats.get("suspicious",0)}
                log.warning("VT: analysis timed out")
                return {"sha256": sha256, "detected": 0, "total": 0, "pending": True}
        return {"sha256": sha256, "detected": 0, "total": 0, "not_found": True}
    except Exception as e:
        log.error(f"VT error: {e}")
        return {"sha256": sha256, "detected": 0, "total": 0, "error": str(e)}

def build_mitre(analysis, behavioral):
    mitre = []
    perms = " ".join(str(analysis.get("permissions",{})))
    apis = str(analysis.get("suspicious_apis",[]))
    bhv = str(behavioral.get("dynamic_behaviors",[]))
    rules = [
        ("T1407","Download New Code at Runtime","Defense Evasion","DexClassLoader" in apis),
        ("T1432","Access Contact List","Collection","READ_CONTACTS" in perms),
        ("T1412","Capture SMS Messages","Collection","READ_SMS" in perms or "RECEIVE_SMS" in perms),
        ("T1430","Location Tracking","Collection","ACCESS_FINE_LOCATION" in perms),
        ("T1417","Input Capture","Collection","AccessibilityService" in apis or "Accessibility" in bhv),
        ("T1411","UI Deception","Credential Access","Banking Overlay" in bhv),
        ("T1406","Obfuscated Files","Defense Evasion","obfuscat" in str(analysis).lower()),
        ("T1437","Standard App Layer Protocol","Command and Control","HttpURLConnection" in apis),
        ("T1418","Software Discovery","Discovery","PackageManager" in apis),
        ("T1438","Alternate Network Mediums","Exfiltration","SEND_SMS" in perms),
    ]
    for tid, name, tactic, triggered in rules:
        if triggered:
            mitre.append({"technique_id": tid, "name": name, "tactic": tactic,
                "confidence": round(0.7 + (hash(tid) % 25)/100, 2)})
    return mitre

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat(),
            "dynamic_analysis": DYNAMIC_AVAILABLE, "version": "2.0.0"}

@app.get("/history")
async def history():
    return {"scans": scan_history[-20:], "total": len(scan_history)}

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "Only .apk files accepted")
    
    log.info(f"Scan: {file.filename}")
    
    file_bytes = await file.read()
    sha256 = get_apk_sha256(file_bytes)
    
    cached = load_cached_result(sha256)
    if cached:
        log.info(f"CACHE HIT: Returning saved analysis for {sha256}")
        cached["cache_hit"] = True
        return cached

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name
        
    try:
        log.info("Static analysis...")
        analysis = analyze_apk(tmp_path)
        
        log.info("Behavioral analysis...")
        behavioral = analyze_behavior(tmp_path, analysis=analysis)
        dynamic = {"status": "not_available", "findings": []}
        
        if DYNAMIC_AVAILABLE:
            pkg = analysis.get("app_info", {}).get("package_name")
            dynamic = run_dynamic_analysis(tmp_path, pkg, analysis=analysis)
            
        log.info("VirusTotal...")
        vt = get_virustotal_result(tmp_path)
        
        log.info("Scoring...")
        score_result = calculate_score(analysis, behavioral, vt)
        
        final_score_data = calculate_final_score(score_result, dynamic)
        risk_score = final_score_data.get("final_score", score_result.get("score", 0))
        static_score = final_score_data.get("static_score", risk_score)
        dynamic_score = final_score_data.get("dynamic_score", 0)
        scoring_mode = final_score_data.get("scoring_mode", "static_only")
        
        log.info(f"Score: {risk_score}/100 (static={static_score}, dynamic={dynamic_score}, mode={scoring_mode})")
        
        ml_result = {}
        if ML_AVAILABLE:
            try:
                ml_result = kmeans_classify(analysis)
                log.info(f"ML: {ml_result.get('ml_classification')} ({ml_result.get('ml_confidence')}%)")
                risk_score = min(100, risk_score + ml_result.get("risk_contribution", 0))
            except Exception as mle:
                log.warning(f"ML error: {mle}")
                
        smali_result = {}
        if SMALI_AVAILABLE:
            try:
                log.info("Smali deobfuscation...")
                smali_result = run_smali_deobfuscation(tmp_path)
                log.info(f"Smali: {smali_result.get('method_count', 0)} methods deobfuscated, threat={smali_result.get('overall_threat_level','?')}")
            except Exception as se:
                log.warning(f"Smali error: {se}")
                
        log.info("AI analysis...")
        ai_result = get_ai_analysis(analysis, score_result)
        
        mitre = build_mitre(analysis, behavioral)
        
        existing_tids = {m.get("technique_id") for m in mitre}
        for sm in score_result.get("mitre", []):
            tid = sm.get("id")
            if tid and tid not in existing_tids:
                mitre.append({
                    "technique_id": tid, 
                    "name": sm.get("name", "Unknown"), 
                    "tactic": sm.get("tactic", "Unknown"), 
                    "confidence": round(0.7 + (hash(tid) % 25)/100, 2)
                })
                existing_tids.add(tid)
                
        threat_intel = {}
        if THREAT_FEEDS_AVAILABLE:
            try:
                sha256_feed = vt.get("sha256", "") or sha256
                urls_in_apk = analysis.get("urls", []) or analysis.get("network", {}).get("urls", [])
                threat_intel = scan_apk_against_feeds(sha256_feed, urls_in_apk)
                log.info(f"Threat intel: {threat_intel.get('threat_level','unknown')}")
            except Exception as te:
                log.warning(f"Threat feeds error: {te}")
                
        scan_history.append({
            "filename": file.filename, "risk_score": risk_score,
            "scan_time": datetime.utcnow().isoformat(),
            "package": analysis.get("app_info", {}).get("package_name") or analysis.get("app_info", {}).get("package", ""),
            "vt_detected": vt.get("detected", 0)})
        save_history(scan_history)
        
        siem_result = {}
        if SIEM_AVAILABLE:
            try:
                alert_payload = {
                    "filename": file.filename, "risk_score": risk_score,
                    "app_info": analysis.get("app_info", {}),
                    "ai_analysis": ai_result, "mitre_mappings": mitre,
                    "virustotal": vt
                }
                siem_result = send_siem_alert(alert_payload)
                log.info(f"SIEM: {siem_result.get('status')}")
            except Exception as se:
                log.warning(f"SIEM error: {se}")
                
        full_result = {
            "filename": file.filename,
            "scan_time": datetime.utcnow().isoformat(),
            "risk_score": risk_score,
            "app_info": analysis.get("app_info", {}),
            "findings": analysis.get("findings", []),
            "permissions": analysis.get("permissions", {}).get("all", []),
            "behavioral": behavioral,
            "dynamic": dynamic,
            "virustotal": vt,
            "ai_analysis": ai_result,
            "mitre_mappings": mitre,
            "threat_intel": threat_intel,
            "siem_alert": siem_result,
            "ml_analysis": ml_result,
            "smali_analysis": smali_result,
            "score_breakdown": final_score_data.get("breakdown", []),
            "dynamic_breakdown": final_score_data.get("dynamic_breakdown", []),
            "static_score": static_score,
            "dynamic_score": dynamic_score,
            "scoring_mode": scoring_mode,
        }
        
        full_result["cache_hit"] = False
        save_result_to_cache(sha256, full_result)
        return full_result
        
    except Exception as e:
        log.error(f"Failed: {e}", exc_info=True)
        raise HTTPException(500, str(e))
    finally:
        try: os.unlink(tmp_path)
        except: pass

@app.post("/report")
async def report(data: dict):
    try:
        from report_generator import generate_pdf_report
        pdf = generate_pdf_report(data)
        return FileResponse(pdf, media_type="application/pdf",
            filename=f"apkguard_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf")
    except Exception:
        return JSONResponse(content=data)

@app.get("/threat-feeds")
async def threat_feeds_endpoint(refresh: bool = False):
    if not THREAT_FEEDS_AVAILABLE:
        raise HTTPException(503, "Threat feeds module not available")
    try:
        feeds = get_threat_feeds(force_refresh=refresh)
        return {
            "status": "ok",
            "last_updated": feeds.get("last_updated"),
            "malwarebazaar_count": len(feeds.get("malwarebazaar", [])),
            "openphish_count": len(feeds.get("openphish", [])),
            "recent_malware": feeds.get("malwarebazaar", [])[:5],
        }
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/siem-test")
async def siem_test():
    if not SIEM_AVAILABLE:
        raise HTTPException(503, "SIEM module not available")
    test_payload = {
        "filename": "test_malware.apk",
        "risk_score": 85,
        "app_info": {"package": "com.evil.malware"},
        "ai_analysis": {
            "malware_family": "BankBot",
            "confidence": "High",
            "threat_summary": "Test alert from APKGuard AI",
            "recommendations": ["Block immediately", "Notify SOC team"]
        },
        "mitre_mappings": [
            {"technique_id": "T1417", "name": "Input Capture", "tactic": "Collection"}
        ],
        "virustotal": {"sha256": "abc123", "detected": 45, "total": 72}
    }
    from siem_webhook import send_siem_alert
    result = send_siem_alert(test_payload)
    return {"test_result": result, "payload_sent": test_payload}

@app.post("/scan-url")
async def scan_url(payload: dict):
    try:
        from url_scanner import scan_message
        message = payload.get("message", payload.get("url", ""))
        if not message:
            raise HTTPException(400, "Provide 'message' or 'url' in request body")
        result = scan_message(message)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/batch-results")
async def get_batch_results():
    import os
    matrix_path = os.path.join(os.path.dirname(__file__), "confusion_matrix.json")
    if not os.path.exists(matrix_path):
        try:
            from batch_tester import run_batch_test
            matrix, results = run_batch_test()
            return {"status": "generated", "matrix": matrix, "results": results}
        except Exception as e:
            raise HTTPException(500, f"Batch test failed: {e}")
    with open(matrix_path) as f:
        data = json.load(f)
    return {"status": "cached", **data}
