import frida
import json
import time
import subprocess
import threading

FRIDA_SCRIPT = """
Java.perform(function() {
    try {
        var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        Editor.putString.implementation = function(key, value) {
            send({type: "creds", key: key, value: value});
            return this.putString(key, value);
        };
    } catch(e) {}

    try {
        var File = Java.use("java.io.File");
        File.$init.overload('java.lang.String').implementation = function(path) {
            if (path && path.indexOf("/data/") >= 0) {
                send({type: "file", path: path});
            }
            return this.$init(path);
        };
    } catch(e) {}

    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
            send({type: "crypto", algo: algo});
            return this.getInstance(algo);
        };
    } catch(e) {}

    send({type: "ready"});
});
"""

def capture_dynamic(package_name, duration=20):
    results = {
        "api_calls": [],
        "file_ops": [],
        "credentials": [],
        "crypto_ops": [],
        "network": [],
        "dynamic_available": False
    }

    try:
        # Forward port
        subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"], capture_output=True, timeout=5)
        
        # Launch app normally first
        subprocess.run(["adb", "shell", "am", "force-stop", package_name], capture_output=True, timeout=5)
        time.sleep(1)
        subprocess.run(["adb", "shell", "am", "start", "-n", f"{package_name}/.MainActivity"], capture_output=True, timeout=5)
        time.sleep(4)

        # Connect via remote gadget
        device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        session = device.attach("Gadget")
        script = session.create_script(FRIDA_SCRIPT)

        def on_message(message, data):
            if message.get("type") == "send":
                payload = message.get("payload", {})
                msg_type = payload.get("type")
                if msg_type == "creds":
                    results["credentials"].append({"key": payload.get("key"), "value": payload.get("value")})
                    results["api_calls"].append({
                        "api": "SharedPreferences.putString",
                        "threat": "high",
                        "class": "android.app.SharedPreferencesImpl",
                        "args": [payload.get("key")]
                    })
                elif msg_type == "file":
                    results["file_ops"].append({"path": payload.get("path"), "operation": "ACCESS", "size_bytes": 0})
                elif msg_type == "crypto":
                    results["crypto_ops"].append({"algorithm": payload.get("algo"), "purpose": "Data encryption"})

        script.on("message", on_message)
        script.load()
        results["dynamic_available"] = True

        print(f"[Frida] Hooked! Monitoring for {duration}s - interact with app NOW!")
        time.sleep(duration)
        session.detach()

        results["summary"] = f"Captured {len(results['api_calls'])} API calls, {len(results['file_ops'])} file ops"
        results["dynamic_risk_score"] = min(100, len(results["api_calls"]) * 10 + len(results["credentials"]) * 20)
        results["total_events"] = len(results["api_calls"]) + len(results["file_ops"]) + len(results["crypto_ops"])

    except Exception as e:
        print(f"[Frida] Error: {e}")
        results["error"] = str(e)

    return results

if __name__ == "__main__":
    result = capture_dynamic("jakhar.aseem.diva", duration=20)
    print(json.dumps(result, indent=2))
