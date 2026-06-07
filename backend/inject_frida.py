#!/usr/bin/env python3
import os, sys, shutil, subprocess, re
from pathlib import Path

GADGET_PATH   = Path.home() / "Downloads/frida-gadget-17.9.8-android-arm64.so"
KEYSTORE_PATH = Path.home() / "apkguard/frida.keystore"
KEYSTORE_PASS = "fridakey"
KEY_ALIAS     = "frida"
WORK_DIR      = Path("/tmp/apkguard_inject")

def run(cmd, check=True):
    print(f"  -> {cmd if isinstance(cmd,str) else ' '.join(cmd)}")
    r = subprocess.run(cmd, shell=isinstance(cmd,str), capture_output=True, text=True)
    if check and r.returncode != 0:
        print(f"  ERROR: {r.stderr}")
        sys.exit(1)
    return r

def get_package_and_activity(apk):
    r = run(["aapt", "dump", "badging", str(apk)], check=False)
    pkg = re.search(r"package: name='([^']+)'", r.stdout)
    act = re.search(r"launchable-activity: name='([^']+)'", r.stdout)
    return (pkg.group(1) if pkg else "unknown"), (act.group(1) if act else None)

def inject_frida(apk_path):
    apk = Path(apk_path).resolve()
    print("\n[1/6] Preparing workspace...")
    if WORK_DIR.exists():
        shutil.rmtree(WORK_DIR)
    WORK_DIR.mkdir(parents=True)

    print("\n[2/6] Decompiling APK...")
    decompiled = WORK_DIR / "decompiled"
    run(["apktool", "d", str(apk), "-o", str(decompiled), "-f", "--no-res"])

    print("\n[3/6] Finding main activity...")
    package, activity = get_package_and_activity(apk)
    if not activity:
        activity = package + ".MainActivity"
    activity_path = activity.replace(".", "/")
    print(f"  -> Package: {package}")
    print(f"  -> Activity: {activity}")

    print("\n[4/6] Copying frida-gadget...")
    lib_dir = decompiled / "lib" / "arm64-v8a"
    lib_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(GADGET_PATH, lib_dir / "libfrida-gadget.so")
    print("  -> Gadget copied")

    print("\n[4b/6] Injecting loadLibrary...")
    load_code = '    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V'
    injected = False
    for smali_dir in list(decompiled.glob("smali*")):
        sf = smali_dir / f"{activity_path}.smali"
        if sf.exists():
            lines = sf.read_text(errors="replace").split("\n")
            new_lines = []
            for line in lines:
                new_lines.append(line)
                if not injected and ".locals" in line:
                    new_lines.append(load_code)
                    injected = True
            sf.write_text("\n".join(new_lines))
            print(f"  -> Injected into {sf.name}")
            break

    print("\n[5/6] Recompiling APK...")
    unsigned = WORK_DIR / "unsigned.apk"
    run(["apktool", "b", str(decompiled), "-o", str(unsigned)])
    aligned = WORK_DIR / "aligned.apk"
    if shutil.which("zipalign"):
        run(["zipalign", "-v", "4", str(unsigned), str(aligned)])
    else:
        shutil.copy(unsigned, aligned)

    print("\n[6/6] Signing APK...")
    signed = Path(str(apk).replace(".apk", "_frida.apk"))
    if shutil.which("apksigner"):
        run(["apksigner", "sign", "--ks", str(KEYSTORE_PATH),
             "--ks-pass", f"pass:{KEYSTORE_PASS}", "--key-pass", f"pass:{KEYSTORE_PASS}",
             "--ks-key-alias", KEY_ALIAS, "--out", str(signed), str(aligned)])
    else:
        shutil.copy(aligned, signed)
        run(["jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1",
             "-keystore", str(KEYSTORE_PATH), "-storepass", KEYSTORE_PASS,
             "-keypass", KEYSTORE_PASS, str(signed), KEY_ALIAS])

    print(f"\nDone! Output: {signed}")
    return str(signed), package

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 inject_frida.py <apk>")
        sys.exit(1)
    signed_apk, package = inject_frida(sys.argv[1])
    ans = input("\nInstall on connected device? (y/n): ").strip().lower()
    if ans == "y":
        run(["adb", "uninstall", package], check=False)
        run(["adb", "install", "-r", "-t", signed_apk])
        run(["adb", "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"])
        print("\nApp running! Connect frida with:")
        print("   frida -U -n Gadget")
