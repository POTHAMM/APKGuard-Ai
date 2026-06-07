import os
import json
import groq
from groq import Groq
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_PROMPT = """You are a senior mobile malware analyst at a banking cybersecurity team.
Analyze Android APK static analysis data and return ONLY valid JSON, no markdown, no explanation.
Return exactly this structure:
{
  "threat_summary": "2-3 sentence plain English summary",
  "malware_family": "Banking Trojan | Spyware | Adware | Ransomware | Unknown | Likely Benign",
  "confidence": "High | Medium | Low",
  "analyst_note": "One sentence senior analyst insight",
  "findings": [{"title": "string", "explanation": "string", "severity": "Critical | High | Medium | Low"}],
  "mitre_techniques": [{"id": "string", "name": "string", "description": "string"}],
  "recommendations": ["string"]
}"""

def build_prompt(analysis, score_data):
    dp = [f"{p['permission'].split('.')[-1]} ({p['reason']})" for p in analysis.get("permissions", {}).get("dangerous", [])]
    apis = [f"{a['api']} - {a['reason']}" for a in analysis.get("suspicious_apis", [])]
    urls = analysis.get("urls_ips", {}).get("urls", [])
    ips = analysis.get("urls_ips", {}).get("ips", [])
    obf = analysis.get("obfuscation", {})
    bi = analysis.get("banking_indicators", [])
    info = analysis.get("app_info", {})
    return f"""Analyze this Android APK and return structured JSON findings.

APP: {info.get('app_name','Unknown')} | Package: {info.get('package','Unknown')}
RISK SCORE: {score_data.get('score',0)}/100 - {score_data.get('severity','UNKNOWN')}

DANGEROUS PERMISSIONS ({len(dp)} found):
{chr(10).join(f'- {p}' for p in dp) if dp else '- None'}

SUSPICIOUS APIS ({len(apis)} found):
{chr(10).join(f'- {a}' for a in apis[:10]) if apis else '- None'}

URLS: {len(urls)} found {('sample: ' + urls[0][:60]) if urls else ''}
IPS: {len(ips)} found {('sample: ' + ips[0]) if ips else ''}
OBFUSCATION: {'DETECTED - ' + '; '.join(obf.get('indicators',[])) if obf.get('detected') else 'Not detected'}
BANKING KEYWORDS: {', '.join(bi) if bi else 'None'}

Return your complete threat intelligence analysis as JSON only."""

def get_ai_analysis(analysis, score_data):
    fallback = {
        "threat_summary": f"Risk score {score_data.get('score',0)}/100 ({score_data.get('severity','UNKNOWN')}). Manual review recommended.",
        "malware_family": "Unknown",
        "confidence": "Low",
        "analyst_note": "AI analysis temporarily unavailable.",
        "findings": [{"title": "Automated Score", "explanation": f"Static analysis score: {score_data.get('score',0)}/100", "severity": "Medium"}],
        "mitre_techniques": score_data.get("mitre", []),
        "recommendations": ["Manually review APK with jadx", "Do not install on any device", "Submit hash to VirusTotal"]
    }

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_prompt(analysis, score_data)},
            ],
            temperature=0.3,
            max_tokens=1500,
            timeout=5.0
        )
        raw = response.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
        
    except groq.APITimeoutError:
        fallback["analyst_note"] = "Groq API request timed out after 5 seconds."
        return fallback
    except groq.APIConnectionError:
        fallback["analyst_note"] = "Could not reach Groq API. Check network or API key."
        return fallback
    except json.JSONDecodeError:
        fallback["analyst_note"] = "AI returned malformed JSON. Raw analysis skipped."
        return fallback
    except Exception as e:
        fallback["analyst_note"] = f"AI unavailable: {str(e)[:100]}"
        return fallback
