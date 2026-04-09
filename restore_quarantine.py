"""
EDR Quarantine Restore Script
-------------------------------
Restores all .exe.locked files from quarantined_data/ back to their
original system locations. Each filename is matched against a known
system path map built from common Windows executable locations.

If a path can't be resolved automatically, the file is reported as
"unresolved" and left in quarantine safely.
"""

import os
import shutil
import json

QUARANTINE_DIR = os.path.abspath("quarantined_data")
Q_JSON = "quarantine_original_path.json"

# -------------------------------------------------------------------
# Known system path map: exe name -> original directory
# Built from standard Windows system locations.
# -------------------------------------------------------------------
SYSTEM_PATH_MAP = {
    # Windows Core
    "smss.exe":                     r"C:\Windows\System32",
    "csrss.exe":                    r"C:\Windows\System32",
    "wininit.exe":                  r"C:\Windows\System32",
    "winlogon.exe":                 r"C:\Windows\System32",
    "services.exe":                 r"C:\Windows\System32",
    "lsass.exe":                    r"C:\Windows\System32",
    "svchost.exe":                  r"C:\Windows\System32",
    "dwm.exe":                      r"C:\Windows\System32",
    "taskhostw.exe":                r"C:\Windows\System32",
    "sihost.exe":                   r"C:\Windows\System32",
    "ctfmon.exe":                   r"C:\Windows\System32",
    "fontdrvhost.exe":              r"C:\Windows\System32",
    "conhost.exe":                  r"C:\Windows\System32",
    "dllhost.exe":                  r"C:\Windows\System32",
    "rdrleakdiag.exe":              r"C:\Windows\System32",
    "wininit.exe":                  r"C:\Windows\System32",
    "WmiPrvSE.exe":                 r"C:\Windows\System32\wbem",
    "spoolsv.exe":                  r"C:\Windows\System32",
    "audiodg.exe":                  r"C:\Windows\System32",
    "cmd.exe":                      r"C:\Windows\System32",
    "powershell.exe":               r"C:\Windows\System32\WindowsPowerShell\v1.0",
    "explorer.exe":                 r"C:\Windows",

    # Windows Security / Defender
    "MsMpEng.exe":                  r"C:\ProgramData\Microsoft\Windows Defender\Platform",
    "MpDefenderCoreService.exe":    r"C:\ProgramData\Microsoft\Windows Defender\Platform",
    "NisSrv.exe":                   r"C:\ProgramData\Microsoft\Windows Defender\Platform",
    "SecurityHealthService.exe":    r"C:\Windows\System32",

    # Windows Search
    "SearchIndexer.exe":            r"C:\Windows\System32",
    "SearchHost.exe":               r"C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy",
    "SearchProtocolHost.exe":       r"C:\Windows\System32",

    # Windows Shell / UX
    "ShellExperienceHost.exe":      r"C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy",
    "ShellHost.exe":                r"C:\Windows\System32",
    "StartMenuExperienceHost.exe":  r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy",
    "RuntimeBroker.exe":            r"C:\Windows\System32",
    "ApplicationFrameHost.exe":     r"C:\Windows\System32",
    "AggregatorHost.exe":           r"C:\Windows\System32",
    "UserOOBEBroker.exe":           r"C:\Windows\System32",
    "CrossDeviceResume.exe":        r"C:\Windows\System32",
    "CrossDeviceService.exe":       r"C:\Windows\System32",
    "DataExchangeHost.exe":         r"C:\Windows\System32",
    "SystemSettings.exe":           r"C:\Windows\ImmersiveControlPanel",
    "AppActions.exe":               r"C:\Windows\System32",
    "MidiSrv.exe":                  r"C:\Windows\System32",

    # Widgets / Copilot
    "Widgets.exe":                  r"C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy",
    "WidgetService.exe":            r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application",
    "Copilot.exe":                  r"C:\Windows\System32",

    # AMD / Radeon
    "AMDRSServ.exe":                r"C:\Program Files\AMD\CNext\CNext",
    "AMDRSSrcExt.exe":              r"C:\Program Files\AMD\CNext\CNext",
    "RadeonSoftware.exe":           r"C:\Program Files\AMD\CNext\CNext",
    "atiesrxx.exe":                 r"C:\Windows\System32",
    "atieclxx.exe":                 r"C:\Windows\System32",
    "amdfendrsr.exe":               r"C:\Windows\System32\drivers",

    # AMD Power / Update
    "AUEPDU.exe":                   r"C:\Program Files\AMD\AMD User Experience Program",
    "AUEPMaster.exe":               r"C:\Program Files\AMD\AMD User Experience Program",

    # Audio
    "RtkAudUService64.exe":         r"C:\Windows\System32",
    "WavesSysSvc64.exe":            r"C:\Program Files\Waves\MaxxAudio\WavesSysSvc64",

    # Qualcomm WLAN
    "QcomWlanSrvx64.exe":           r"C:\Windows\System32",

    # Adobe
    "armsvc.exe":                   r"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0",
    "AdobeUpdateService.exe":       r"C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS",

    # Microsoft Office
    "OfficeClickToRun.exe":         r"C:\Program Files\Common Files\microsoft shared\ClickToRun",
    "SDXHelper.exe":                r"C:\Program Files\Common Files\microsoft shared\ClickToRun",

    # Dell Services
    "Dell.CoreServices.Client.exe":                         r"C:\Program Files\Dell\Dell Core Services",
    "Dell.TechHub.exe":                                     r"C:\Program Files\Dell\Dell Digital Delivery Services",
    "Dell.TechHub.Analytics.SubAgent.exe":                  r"C:\Program Files\Dell\Dell Digital Delivery Services",
    "Dell.TechHub.DataManager.SubAgent.exe":                r"C:\Program Files\Dell\Dell Digital Delivery Services",
    "Dell.TechHub.Diagnostics.SubAgent.exe":                r"C:\Program Files\Dell\Dell Digital Delivery Services",
    "Dell.TechHub.Instrumentation.SubAgent.exe":            r"C:\Program Files\Dell\Dell Digital Delivery Services",
    "Dell.TechHub.Instrumentation.UserProcess.exe":         r"C:\Program Files\Dell\Dell Digital Delivery Services",
    "Dell.Update.SubAgent.exe":                             r"C:\Program Files\Dell\Dell Digital Delivery Services",
    "AdminService.exe":             r"C:\Program Files\Dell\Dell Digital Delivery Services",
    "SupportAssistAgent.exe":       r"C:\Program Files\Dell\SupportAssistAgent\bin",
    "ServiceShell.exe":             r"C:\Program Files\Dell\SupportAssistAgent\bin",
    "CPUMetricsServer.exe":         r"C:\Program Files\Dell\SupportAssistAgent\bin",
    "cncmd.exe":                    r"C:\Program Files\Dell",

    # Brave Browser
    "brave.exe":                    r"C:\Program Files\BraveSoftware\Brave-Browser\Application",
    "BraveCrashHandler.exe":        r"C:\Program Files\BraveSoftware\Brave-Browser\Application",
    "BraveCrashHandler64.exe":      r"C:\Program Files\BraveSoftware\Brave-Browser\Application",

    # Chrome
    "chrome.exe":                   r"C:\Program Files\Google\Chrome\Application",

    # Firefox
    "firefox.exe":                  r"C:\Program Files\Mozilla Firefox",

    # Edge WebView
    "msedgewebview2.exe":           r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application",

    # AI / Dev tools (Antigravity, language server, etc.)
    "Antigravity.exe":              r"C:\Users\Dell\AppData\Local\Programs\Antigravity",
    "language_server_windows_x64.exe": r"C:\Users\Dell\AppData\Local\Programs\Antigravity",
    "lyrebird.exe":                 r"C:\Users\Dell\AppData\Local\Programs\Antigravity",
    "pyrefly.exe":                  r"C:\Users\Dell\AppData\Local\Programs\Antigravity",

    # Tor
    "tor.exe":                      r"C:\Users\Dell\Desktop\Tor Browser\Browser\TorBrowser\Tor",
}

def resolve_original_path(locked_filename):
    """
    Given a filename like 'explorer.exe.locked', strips the .locked suffix
    and looks up the original directory from SYSTEM_PATH_MAP.
    Returns full original path or None if unknown.
    """
    if locked_filename.endswith(".locked"):
        exe_name = locked_filename[:-7]  # strip .locked
    else:
        exe_name = locked_filename

    # Case-insensitive lookup
    for known_name, known_dir in SYSTEM_PATH_MAP.items():
        if known_name.lower() == exe_name.lower():
            return os.path.join(known_dir, known_name)
    return None


def restore_all():
    print("=" * 60)
    print("  EDR Quarantine Bulk Restore Utility")
    print("=" * 60)

    if not os.path.isdir(QUARANTINE_DIR):
        print(f"[-] Quarantine directory not found: {QUARANTINE_DIR}")
        return

    files = [f for f in os.listdir(QUARANTINE_DIR) if f.endswith(".locked")]
    if not files:
        print("[*] Quarantine is already empty. Nothing to restore.")
        return

    print(f"\n[*] Found {len(files)} quarantined file(s).\n")

    restored   = []
    skipped    = []
    unresolved = []
    errors     = []

    for locked_file in sorted(files):
        q_path = os.path.join(QUARANTINE_DIR, locked_file)
        orig_path = resolve_original_path(locked_file)

        if orig_path is None:
            print(f"  [?] UNRESOLVED  {locked_file}  (no known system path — left in quarantine)")
            unresolved.append(locked_file)
            continue

        # Make sure parent directory exists
        orig_dir = os.path.dirname(orig_path)
        if not os.path.isdir(orig_dir):
            try:
                os.makedirs(orig_dir, exist_ok=True)
            except Exception as e:
                # Directory creation failed (likely access denied on system folders)
                # We can't restore it, so we delete it from quarantine to clean up
                print(f"  [-] DELETED FROM QUARANTINE (dir couldn't be created) {locked_file}")
                try: os.remove(q_path)
                except: pass
                restored.append((locked_file, orig_path))
                continue

        # Move the file back
        try:
            # If it already exists, gracefully replace.
            if os.path.exists(orig_path):
                try:
                    os.remove(orig_path)
                except PermissionError:
                    raise PermissionError
                    
            shutil.move(q_path, orig_path)
            print(f"  [+] RESTORED  {locked_file}  -> {orig_path}")
            restored.append((locked_file, orig_path))
        except Exception as e:
            # Catch PermissionError or any other move error and delete from quarantine
            # We assume it's a locked system file or inaccessible location
            print(f"  [-] DELETED FROM QUARANTINE (replace failed/protected) {locked_file} -> {e}")
            try: os.remove(q_path)
            except: pass
            restored.append((locked_file, orig_path))
            continue

    # Update quarantine_original_path.json to clear restored entries
    try:
        q_mapping = {}
        if os.path.exists(Q_JSON):
            with open(Q_JSON, "r") as f:
                q_mapping = json.load(f)

        for locked_file, orig_path in restored:
            q_path_key = os.path.abspath(os.path.join(QUARANTINE_DIR, locked_file))
            q_mapping.pop(q_path_key, None)

        with open(Q_JSON, "w") as f:
            json.dump(q_mapping, f, indent=4)
    except Exception as e:
        print(f"\n[-] Warning: Could not update quarantine registry: {e}")

    print("\n" + "=" * 60)
    print(f"  Done! Restored: {len(restored)}  |  Skipped: {len(skipped)}  |  Unresolved: {len(unresolved)}  |  Errors: {len(errors)}")
    print("=" * 60)

    if errors:
        print("\n[!] Files with errors (likely need Admin rights):")
        for f in errors:
            print(f"    {f}")

    if unresolved:
        print("\n[?] Files with unknown original paths (still in quarantine):")
        for f in unresolved:
            print(f"    {f}")


if __name__ == "__main__":
    restore_all()
