import zipfile

def analyze_behavior(apk_path: str, androguard_dx=None, analysis: dict = None) -> dict:
    runtime_indicators = []
    dynamic_behaviors = []
    anti_analysis = []

    # ── USE ALREADY-PARSED DATA FROM ANDROGUARD ──
    if analysis:
        dangerous_perms = [p["permission"].replace("android.permission.", "") for p in analysis.get("permissions", {}).get("dangerous", [])]
        all_perms = analysis.get("permissions", {}).get("all", [])
        all_perms_combined = set(dangerous_perms + (all_perms if isinstance(all_perms, list) else []))

        suspicious_apis = analysis.get("suspicious_apis", [])
        api_names = set()
        for a in suspicious_apis:
            if isinstance(a, str):
                api_names.add(a)
            elif isinstance(a, dict):
                api_names.add(a.get("api", "") or a.get("name", ""))

        # Combine permission names + api names into one searchable set
        all_indicators = all_perms_combined | api_names

        # Also do raw binary scan as fallback for strings not in parsed data
        raw_content = ""
        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                for name in z.namelist():
                    try:
                        raw_content += z.read(name).decode("latin-1", errors="replace")
                    except Exception:
                        pass
        except Exception:
            pass

        def found(pattern):
            return pattern in all_indicators or pattern in raw_content

    else:
        # fallback: raw binary only
        raw_content = ""
        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                for name in z.namelist():
                    try:
                        raw_content += z.read(name).decode("latin-1", errors="replace")
                    except Exception:
                        pass
        except Exception:
            pass
        def found(pattern):
            return pattern in raw_content

    # ── RUNTIME INDICATORS ──
    runtime_checks = [
        ("RECEIVE_BOOT_COMPLETED",  "Auto-start on device boot",              "Persistence"),
        ("READ_SMS",                "Can read SMS messages including OTPs",    "Data Exfiltration"),
        ("SEND_SMS",                "Can send SMS without user knowledge",     "Data Exfiltration"),
        ("RECEIVE_SMS",             "Intercepts incoming SMS messages",        "Surveillance"),
        ("READ_CALL_LOG",           "Access to full call history",             "Data Exfiltration"),
        ("RECORD_AUDIO",            "Audio recording capability",              "Surveillance"),
        ("CAMERA",                  "Camera access detected",                  "Surveillance"),
        ("READ_CONTACTS",           "Contacts database access",                "Data Exfiltration"),
        ("READ_PHONE_STATE",        "Reads IMEI and device identifiers",       "Surveillance"),
        ("PROCESS_OUTGOING_CALLS",  "Can intercept outgoing calls",            "Surveillance"),
        ("AccessibilityService",    "Accessibility service abuse detected",    "Credential Theft"),
        ("DeviceAdminReceiver",     "Device administrator privileges",         "Persistence"),
        ("SmsManager",              "SMS sending via API",                     "Data Exfiltration"),
        ("AudioRecord",             "Direct audio recording API",              "Surveillance"),
        ("LocationManager",         "GPS location tracking",                   "Surveillance"),
        ("KeyguardManager",         "Screen lock bypass attempt",              "Privilege Escalation"),
        ("PackageInstaller",        "Silent APK installation capability",      "Malware Dropper"),
        ("ClipboardManager",        "Clipboard monitoring",                    "Data Theft"),
        ("ContactsContract",        "Contacts database direct access",         "Data Exfiltration"),
        ("TelephonyManager",        "Phone state and IMEI monitoring",         "Surveillance"),
        ("SYSTEM_ALERT_WINDOW",     "Can draw over other apps (overlay)",      "Credential Theft"),
        ("WRITE_EXTERNAL_STORAGE",  "Can write to external storage",           "Data Exfiltration"),
        ("INTERNET",                "Network access for data exfiltration",    "Data Exfiltration"),
    ]

    for pattern, desc, category in runtime_checks:
        if found(pattern):
            runtime_indicators.append({
                "indicator": pattern,
                "description": desc,
                "category": category
            })

    # ── ANTI-ANALYSIS TECHNIQUES ──
    evasion_checks = [
        ("isEmulator",   "Emulator detection — avoids sandbox analysis"),
        ("FINGERPRINT",  "Device fingerprint check — anti-emulator"),
        ("isDebugger",   "Debugger detection — anti-analysis"),
        ("ro.secure",    "Root detection check"),
        ("Xposed",       "Xposed hook detection"),
        ("frida",        "Frida detection — anti-dynamic-analysis"),
        ("BuildConfig",  "Build configuration inspection"),
        ("isRooted",     "Root access check"),
        ("su\x00",      "su binary detection for root"),
    ]

    for pattern, desc in evasion_checks:
        if found(pattern):
            anti_analysis.append({
                "technique": pattern,
                "description": desc
            })

    # ── DYNAMIC BEHAVIORS (composite logic) ──
    has_overlay      = found("SYSTEM_ALERT_WINDOW")
    has_accessibility= found("AccessibilityService")
    has_sms_read     = found("READ_SMS")
    has_sms_receive  = found("RECEIVE_SMS")
    has_sms_send     = found("SEND_SMS")
    has_dex_loader   = found("DexClassLoader")
    has_audio        = found("RECORD_AUDIO") or found("AudioRecord")
    has_camera       = found("CAMERA")
    has_admin        = found("DeviceAdminReceiver")
    has_boot         = found("RECEIVE_BOOT_COMPLETED")
    has_contacts     = found("READ_CONTACTS") or found("ContactsContract")
    has_call_log     = found("READ_CALL_LOG")
    has_location     = found("LocationManager")
    has_internet     = found("INTERNET")
    has_keyguard     = found("KeyguardManager")
    has_pkg_install  = found("PackageInstaller")

    if has_overlay and has_accessibility:
        dynamic_behaviors.append({
            "behavior": "Banking Overlay Attack",
            "description": "Displays fake login screens over banking apps to steal credentials",
            "severity": "Critical"
        })
    if has_sms_read and has_sms_receive:
        dynamic_behaviors.append({
            "behavior": "OTP/SMS Interception",
            "description": "Intercepts incoming SMS including one-time passwords for 2FA bypass",
            "severity": "Critical"
        })
    if has_sms_send and has_internet:
        dynamic_behaviors.append({
            "behavior": "SMS Exfiltration",
            "description": "Sends stolen data via SMS and network to remote server",
            "severity": "High"
        })
    if has_dex_loader:
        dynamic_behaviors.append({
            "behavior": "Dynamic Code Loading",
            "description": "Downloads and executes additional malicious code at runtime",
            "severity": "High"
        })
    if has_audio:
        dynamic_behaviors.append({
            "behavior": "Audio Surveillance",
            "description": "Secretly records audio from device microphone",
            "severity": "High"
        })
    if has_camera:
        dynamic_behaviors.append({
            "behavior": "Camera Surveillance",
            "description": "Secretly captures photos or video using device camera",
            "severity": "High"
        })
    if has_admin:
        dynamic_behaviors.append({
            "behavior": "Device Admin Abuse",
            "description": "Requests device administrator privileges to prevent uninstallation",
            "severity": "High"
        })
    if has_boot:
        dynamic_behaviors.append({
            "behavior": "Persistence via Boot",
            "description": "Automatically starts on device reboot to maintain persistence",
            "severity": "Medium"
        })
    if has_contacts and has_internet:
        dynamic_behaviors.append({
            "behavior": "Contact Exfiltration",
            "description": "Harvests contacts and sends them to a remote server",
            "severity": "High"
        })
    if has_call_log:
        dynamic_behaviors.append({
            "behavior": "Call Log Harvesting",
            "description": "Reads full call history for surveillance and exfiltration",
            "severity": "Medium"
        })
    if has_location:
        dynamic_behaviors.append({
            "behavior": "GPS Tracking",
            "description": "Continuously monitors device location for stalkerware behavior",
            "severity": "Medium"
        })
    if has_keyguard:
        dynamic_behaviors.append({
            "behavior": "Screen Lock Bypass",
            "description": "Attempts to bypass device screen lock",
            "severity": "High"
        })
    if has_pkg_install:
        dynamic_behaviors.append({
            "behavior": "Dropper Behavior",
            "description": "Can silently install additional APKs — classic dropper/stager pattern",
            "severity": "Critical"
        })

    return {
        "runtime_indicators": runtime_indicators,
        "anti_analysis_techniques": anti_analysis,
        "dynamic_behaviors": dynamic_behaviors,
        "total_runtime_indicators": len(runtime_indicators),
        "evasion_detected": len(anti_analysis) > 0,
    }
