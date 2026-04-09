import os
import time
import shutil
import threading
import math
import psutil
import pandas as pd
import joblib
import json
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

TARGET_DIR = "dummy_data"
BACKUP_DIR = "edr_backup"
MODEL_PATH = "edr_model.pkl"
QUARANTINE_DIR = "quarantined_data"

recent_processes_cache = {}
entropy_cache = {}
entropy_lock = threading.Lock()

def track_processes_loop():
    # Cache all initial processes once so we don't lag on startup
    for p in psutil.pids():
        try:
            recent_processes_cache[p] = {'last_seen': time.time()} # lightweight placeholder
        except Exception: pass
        
    def gather_info_sync(pid, current_time):
        try:
            if not psutil.pid_exists(pid):
                return
            proc = psutil.Process(pid)
            # FAST AS POSSIBLE: Minimal attributes first
            info = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'exe', 'create_time'])
            try:
                cwd = proc.cwd()
            except:
                cwd = None
                
            recent_processes_cache[pid] = {
                'info': info,
                'cwd': cwd,
                'last_seen': current_time,
                'first_seen': info.get('create_time') or current_time,
                'io_snapshot': proc.io_counters() if hasattr(proc, 'io_counters') else None
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            recent_processes_cache[pid] = {'last_seen': current_time}

    while True:
        try:
            current_time = time.time()
            current_pids = psutil.pids()
            
            for pid in current_pids:
                if pid not in recent_processes_cache or 'info' not in recent_processes_cache[pid]:
                    # Process NEW PID immediately in the same loop to avoid thread explosion
                    gather_info_sync(pid, current_time)
                else:
                    recent_processes_cache[pid]['last_seen'] = current_time
                    
            # Clean up old (keep for 120 seconds to catch delayed detections)
            for pid in list(recent_processes_cache.keys()):
                if current_time - recent_processes_cache[pid]['last_seen'] > 120.0:
                    del recent_processes_cache[pid]
        except Exception: pass
        time.sleep(0.01) # Poll at 10ms (100Hz) - balanced performance and safety

class EDRMonitor(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.events_queue = deque()
        self.lock = threading.Lock()

    def on_modified(self, event):
        if not event.is_directory:
            with self.lock:
                self.events_queue.append(('modified', time.time(), event.src_path))

    def on_created(self, event):
        if not event.is_directory:
            with self.lock:
                self.events_queue.append(('created', time.time(), event.src_path))

    def on_deleted(self, event):
        if not event.is_directory:
            with self.lock:
                self.events_queue.append(('deleted', time.time(), event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            with self.lock:
                self.events_queue.append(('renamed', time.time(), event.dest_path))

def calculate_entropy(file_path):
    try:
        if not os.path.exists(file_path):
            return 0.0
            
        mtime = os.path.getmtime(file_path)
        cache_key = (file_path, mtime)
        
        with entropy_lock:
            if cache_key in entropy_cache:
                return entropy_cache[cache_key]
                
        with open(file_path, "rb") as f:
            data = f.read(1024) # Read a chunk to approximate entropy fast
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        
        with entropy_lock:
            entropy_cache[cache_key] = entropy
            # Basic cache eviction if too large
            if len(entropy_cache) > 2000:
                entropy_cache.clear()
                
        return entropy
    except Exception:
        return 0.0

def create_shadow_copy():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    else:
        shutil.rmtree(BACKUP_DIR)
        os.makedirs(BACKUP_DIR)
        
    path_mapping = {}
    
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            original_path = os.path.abspath(os.path.join(root, file))
            new_filename = f"{int(time.time())}_{file}.locked"
            new_path = os.path.abspath(os.path.join(BACKUP_DIR, new_filename))
            
            shutil.copy2(original_path, new_path)
            path_mapping[new_path] = original_path

    with open("original_path.json", "w") as f:
        json.dump(path_mapping, f, indent=4)
        
    print(f"[*] Created shadow copy of files into {BACKUP_DIR} obfuscated as .locked files.")

def restore_from_backup():
    print("[!] RESTORING FILES FROM BACKUP...")
    
    if not os.path.exists("original_path.json"):
        print("[-] original_path.json not found! Cannot restore.")
        return
        
    with open("original_path.json", "r") as f:
        path_mapping = json.load(f)
        
    for backup_path, original_path in path_mapping.items():
        if os.path.exists(backup_path):
            restored_path = original_path
            if restored_path.endswith('.locked'):
                restored_path = restored_path[:-7]
                
            malicious_locked_file = restored_path + '.locked'
            if os.path.exists(malicious_locked_file):
                try:
                    os.remove(malicious_locked_file)
                except:
                    pass
                    
            os.makedirs(os.path.dirname(restored_path), exist_ok=True)
            shutil.copy2(backup_path, restored_path)
            
    print(f"[+] Restoration complete!")

def load_whitelist():
    whitelist = set()
    if os.path.exists("whitelist.txt"):
        try:
            with open("whitelist.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Keep whitelist comparisons lowercase for safety
                        whitelist.add(line.lower())
        except Exception:
            pass
    return whitelist

def is_whitelisted(exe_path, name, whitelist, bypass_whitelist=False):
    # Core Whitelist: NEVER kill these processes, even if 'loud'
    CORE_WHITELIST = {'antigravity.exe', 'antigravity', 'python.exe', 'python', 'python3.exe', 'python3', 'pythonw.exe', 'pythonw', 'pip.exe', 'npm.exe', 'node.exe'}
    if 'python3.' in name.lower() or 'pythonw' in name.lower():
        CORE_WHITELIST.add(name.lower())
    
    if not exe_path:
        exe_path = ""
    path_lower = exe_path.lower()
    name_lower = name.lower()
    
    # 0. Check Core Whitelist
    # Use basename for core whitelist to avoid whitelisting entire directories with 'antigravity' in name
    filename = os.path.basename(path_lower)
    if any(x == filename or x == name_lower for x in CORE_WHITELIST):
        if not bypass_whitelist:
            return True

    if bypass_whitelist:
        return False # Force a deep look for everything else
    
    # 1. Check user-defined whitelist.txt
    if path_lower in whitelist or name_lower in whitelist:
        return True
        
    # 2. Automatically ignore the entire Windows directory for safety
    if 'c:\\windows' in path_lower:
        return True
    
    # 3. Ignore legitimate Python standard libraries and IDLE
    if 'idlelib' in path_lower or 'site-packages' in path_lower or 'lib\\' in path_lower:
        # Check if it's in the official Python install directory
        if 'python' in path_lower and ('programs' in path_lower or 'microsoft\\visualstudio' in path_lower):
            return True
            
    # 4. Ignore trusted Program Files and AppData (unless they are suspicious temp ones)
    if ('program files' in path_lower or 'appdata\\local' in path_lower) and 'temp' not in path_lower:
        # Avoid whitelisting 'dell' just because it's a username - make it a more specific system check
        if any(x in path_lower for x in ['microsoft', 'google', 'adobe', 'nvidia', 'amd', 'bravesoftware']):
            return True
        # Only whitelist Dell-specific software if it's in a known program directory, not just any path with 'dell'
        if 'program files\\dell\\' in path_lower or 'appdata\\local\\dell\\' in path_lower:
            return True

    return False

def quarantine_dead_file(exe_path):
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
    
    if not exe_path or not os.path.exists(exe_path):
        return False

    filename = os.path.basename(exe_path)
    quarantine_path = os.path.join(QUARANTINE_DIR, f"{filename}.locked")
    
    print(f"[*] Quarantining malicious dead file: {exe_path} -> {quarantine_path}")
    
    try:
        shutil.move(exe_path, quarantine_path)
        print(f"[+] Malware successfully quarantined to {quarantine_path}")
        
        q_mapping = {}
        q_json = "quarantine_original_path.json"
        if os.path.exists(q_json):
            try:
                with open(q_json, "r") as f:
                    q_mapping = json.load(f)
            except Exception: pass
        
        q_mapping[os.path.abspath(quarantine_path)] = os.path.abspath(exe_path)
        with open(q_json, "w") as f:
            json.dump(q_mapping, f, indent=4)
        return True
    except Exception as e:
        print(f"[-] Failed to move dead malware: {e}")
        return False

def quarantine_malware(proc):
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
            
        exe_path = proc.exe()
        name = proc.name().lower()
        try: cmdline = proc.cmdline()
        except: cmdline = []
        
        # MASSIVE SAFEGUARD: Prevent killing Antigravity or ANY IDE backend
        # Note: Do not use 'antigravity' alone because the folder is 'edr_antigravity'
        safe_keywords = ['antigravity.exe', 'pyright', 'vscode', 'jedi', 'language_server', 'language-server', 'pylsp']
        cmd_str = " ".join([str(a).lower() for a in cmdline])
        if any(safe in cmd_str for safe in safe_keywords):
            print(f"[*] SKIPPING QUARANTINE: Process '{name}' contains IDE/Backend keywords and is protected.")
            return

        target_path = exe_path
        
        # Prevent wiping system python or other interpreters
        if 'python' in name and cmdline:
            for arg in cmdline[1:]:
                if str(arg).endswith('.py'):
                    abs_arg = os.path.abspath(arg)
                    try: cwd = proc.cwd()
                    except: cwd = None
                    if not os.path.exists(abs_arg) and cwd:
                        abs_arg = os.path.abspath(os.path.join(cwd, arg))
                    if os.path.exists(abs_arg):
                        target_path = abs_arg
                        break
        
        if not target_path or not os.path.exists(target_path):
            proc_name = getattr(proc, 'info', {}).get('name') or proc.name() or 'Unknown'
            print(f"[-] Could not find executable path for quarantine: {proc_name}")
            return

        filename = os.path.basename(target_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{filename}.locked")
        
        print(f"[*] Quarantining malicious file: {target_path} -> {quarantine_path}")
        
        try:
            # Safely get name and pid
            p_name = getattr(proc, 'info', {}).get('name') or proc.name() or 'Unknown'
            p_pid = getattr(proc, 'info', {}).get('pid') or proc.pid

            # First kill the process so the file gets unlocked by the OS
            proc.kill()
            print(f"[+] Killed Process {p_name} ({p_pid})")
            
            # Allow a brief moment for the OS to release the file handle
            time.sleep(1)
            
            # Now move and rename the executable
            if os.path.exists(target_path):
                shutil.move(target_path, quarantine_path)
                print(f"[+] Malware successfully quarantined to {quarantine_path}")
                
                # Record the original path mappings safely
                q_mapping = {}
                q_json = "quarantine_original_path.json"
                if os.path.exists(q_json):
                    try:
                        with open(q_json, "r") as f:
                            q_mapping = json.load(f)
                    except Exception:
                        pass
                
                q_mapping[os.path.abspath(quarantine_path)] = os.path.abspath(target_path)
                with open(q_json, "w") as f:
                    json.dump(q_mapping, f, indent=4)
        except Exception as e:
            print(f"[-] Failed to move malware to quarantine: {e}")

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        print(f"[-] Error during quarantine: {e}")

def kill_ransomware_process(anomaly_window_start=None, anomaly_hint_path=None):
    print("[!] SEARCHING FOR MALICIOUS PROCESS TO TERMINATE AND QUARANTINE...")
    current_time = time.time()
    
    # EDR PID to protect ourselves
    my_pid = os.getpid()
    target_abs_path = os.path.abspath(TARGET_DIR).lower()

    # Load dynamic whitelist from file
    whitelist = load_whitelist()
    edr_script_path = os.path.abspath(__file__).lower()

    # --- FAILSAFE FOR SPECIFIC MALWARE FILES ---
    failsafe_targets = [
        os.path.abspath("ransomware.py").lower(),
        r"c:\users\dell\appdata\local\programs\python\python313\beast_mode\encrypt\encrypt.py"
    ]
    
    quarantined_failsafe = False
    
    for pid in psutil.pids():
        try:
            if pid == my_pid or pid == 0: continue
            proc = psutil.Process(pid)
            try: cmdline = proc.cmdline()
            except: cmdline = []
            try: name = proc.name().lower()
            except: name = ""
            
            if 'python' in name and cmdline:
                cmd_str = " ".join([str(a).lower() for a in cmdline])
                if any(safe in cmd_str for safe in ['antigravity.exe', 'pyright', 'vscode', 'jedi', 'language_server', 'language-server', 'pylsp', 'edr.py', 'unquarantine.py']):
                    continue
                    
                malicious_path = None
                
                # Extract script from cmdline args
                for arg in cmdline[1:]:
                    arg_lower = str(arg).lower()
                    if arg_lower.startswith('-'): continue
                    if not arg_lower.endswith('.py') and not arg_lower.endswith('.pyw') and not arg_lower.endswith('.exe'): continue
                    
                    abs_arg = os.path.abspath(arg_lower)
                    if abs_arg != edr_script_path and not os.path.basename(abs_arg) in ['edr.py', 'unquarantine.py']:
                        malicious_path = abs_arg
                        break
                        
                # Extract script from open file handles (Catches IDLE execution)
                if not malicious_path:
                    try:
                        for f in proc.open_files():
                            if f.path.endswith('.py') and 'lib\\' not in f.path.lower():
                                abs_path = os.path.abspath(f.path)
                                if abs_path != edr_script_path and os.path.basename(abs_path) not in ['edr.py', 'unquarantine.py']:
                                    malicious_path = abs_path
                                    break
                    except (psutil.AccessDenied, psutil.NoSuchProcess): pass
                    
                if malicious_path and is_whitelisted(malicious_path, os.path.basename(malicious_path), whitelist):
                    malicious_path = None
                    
                if malicious_path:
                    print(f"[!] AGGRESSIVE FAILSAFE: Terminating suspected Python script PID {pid} -> {malicious_path}")
                    try: proc.kill()
                    except: pass
                    if quarantine_dead_file(malicious_path):
                        quarantined_failsafe = True
                else:
                    # If we can't find the source file, we kill the runner itself but don't quarantine Python's core binaries.
                    exe_path = proc.exe()
                    print(f"[!] AGGRESSIVE FAILSAFE: Terminating blind Python runner PID {pid} ({cmd_str})")
                    try: proc.kill()
                    except: pass
                    if exe_path and not is_whitelisted(exe_path, name, whitelist):
                        if quarantine_dead_file(exe_path):
                            quarantined_failsafe = True
        except (psutil.NoSuchProcess, psutil.AccessDenied): pass

    # Check 2: Memory Cache (for scripts that ran incredibly fast and already died)
    for pid, data in list(recent_processes_cache.items()):
        if pid == my_pid or pid == 0: continue
        info = data.get('info', {})
        cmdline = info.get('cmdline', [])
        name = info.get('name', '').lower()
        if not cmdline: continue
        
        if 'python' in name:
            cmd_str = " ".join([str(a).lower() for a in cmdline])
            if any(safe in cmd_str for safe in ['antigravity.exe', 'pyright', 'vscode', 'jedi', 'language_server', 'language-server', 'pylsp', 'edr.py', 'unquarantine.py']):
                continue
                
            malicious_path = None
            for arg in cmdline[1:]:
                arg_lower = str(arg).lower()
                if arg_lower.startswith('-'): continue
                if not arg_lower.endswith('.py') and not arg_lower.endswith('.pyw') and not arg_lower.endswith('.exe'): continue
                
                abs_arg = os.path.abspath(arg_lower)
                if abs_arg != edr_script_path and not os.path.basename(abs_arg) in ['edr.py', 'unquarantine.py']:
                    malicious_path = abs_arg
                    break
                    
            # Ensure it was run VERY recently (within last 30 sec) to avoid quarantining 
            # from a distant past execution if we somehow retained it
            last_seen = data.get('last_seen', 0)
            if current_time - last_seen < 30.0:
                if malicious_path and is_whitelisted(malicious_path, os.path.basename(malicious_path), whitelist):
                    malicious_path = None
                    
                if malicious_path:
                    print(f"[!] AGGRESSIVE FAILSAFE MEMORY: Found target malware script in memory cache PID {pid}")
                    if quarantine_dead_file(malicious_path):
                        quarantined_failsafe = True
                else:
                    # In memory cache, if we didn't find the source through cmdline, we can't access open_files anymore.
                    # Exe quarantine fallback if applicable
                    exe_path = info.get('exe')
                    if exe_path and not is_whitelisted(exe_path, name, whitelist):
                        print(f"[!] AGGRESSIVE FAILSAFE MEMORY: Suspected blind execution, logging mitigation. PID {pid}")
                        if quarantine_dead_file(exe_path):
                            quarantined_failsafe = True

    if quarantined_failsafe:
        return True
    # ---------------------------------------------

    # Heuristic 0: Identify processes with high I/O writing spikes (Loudness Header)
    loudest_pids = []
    for pid in psutil.pids():
        if pid == my_pid or pid == 0: continue
        try:
            proc = psutil.Process(pid)
            current_io = proc.io_counters()
            if pid in recent_processes_cache and 'io_snapshot' in recent_processes_cache[pid]:
                old_io = recent_processes_cache[pid]['io_snapshot']
                if old_io and current_io:
                    write_delta = current_io.write_bytes - old_io.write_bytes
                    if write_delta > 50000: # Over 0.05MB (Catch simulation I/O spikes)
                        name = (getattr(proc, 'info', {}).get('name') or proc.name()).lower()
                        exe_path = proc.exe().lower()
                        loudest_pids.append((pid, name, exe_path, write_delta))
        except: continue
    
    if loudest_pids:
        loudest_pids.sort(key=lambda x: x[3], reverse=True)
        print(f"[*] Identified {len(loudest_pids)} processes with significant I/O activity.")

    # Heuristic 1: Behavioral Memory Scan (Temporal Correlation) - FAST
    print(f"[*] Checking Process Memory Cache for activity during anomaly window (Start: {anomaly_window_start if anomaly_window_start else 'N/A'})...")
    
    suspicious_pids = []
    
    # If we don't have a window, assume last 5 seconds
    if not anomaly_window_start:
        anomaly_window_start = current_time - 5.0

    # GRACE PERIOD (5 seconds): Allows us to catch "hit-and-run" processes that 
    # exited slightly BEFORE the anomaly reached the detection threshold.
    anomaly_buffer = 5.0
    
    for pid, data in list(recent_processes_cache.items()):
        if pid == my_pid: continue
        
        info = data.get('info')
        if not info: continue
        
        cmdline = info.get('cmdline') or []
        name = (info.get('name') or '').lower()
        exe_path = (info.get('exe') or '').lower()
        
        last_seen = data.get('last_seen', 0)
        os_create_time = info.get('create_time')
        first_seen = os_create_time if os_create_time else data.get('first_seen', current_time)
        
        # Overlap check (with 2s grace period for fast-exiting scripts)
        is_active_during_anomaly = (last_seen >= (anomaly_window_start - anomaly_buffer)) and (first_seen <= current_time)
        
        if is_active_during_anomaly:
            is_interpreter = any(x in name for x in ['python', 'powershell', 'cmd.exe', 'wscript', 'cscript', 'bash', 'pwsh']) or \
                             any(x in exe_path for x in ['python', 'powershell', 'cmd.exe', 'wscript', 'cscript', 'bash', 'pwsh'])
            
            # If it's a known interpreter, we MUST investigate it even if it's whitelisted
            if is_whitelisted(exe_path, name, whitelist, bypass_whitelist=False) and not is_interpreter:
                continue

            proc_age = last_seen - first_seen
            
            # STRICTOR FP FILTERING: Ignore non-interpreters unless they are essentially brand new (< 15s)
            # Legitimate app updates like braveupdate.exe often run for 30s-2min.
            if not is_interpreter and proc_age > 15.0:
                continue

            print(f"  [DEBUG-TEMPORAL] PID {pid} | Name: '{name}' | Age: {proc_age:.2f}s | active: {is_active_during_anomaly}")

            if proc_age < 180.0 or is_interpreter: # increased limit to 3min
                suspicious_pids.append((pid, name or os.path.basename(exe_path) or 'unknown', cmdline, exe_path, data.get('cwd'), proc_age))

    # Analyze based on sorted suspicion
    # 1. Loudest PIDs first (I/O Spike check)
    for pid, name, exe_path, delta in loudest_pids:
        print(f"  [LOUD-PROC] PID {pid} ({name}) I/O Write Delta: {delta/1024/1024:.2f}MB")
        # Bypass whitelist for exceptionally loud activity
        if not is_whitelisted(exe_path, name, whitelist, bypass_whitelist=True):
            # Check for handles and scripts
            try:
                proc = psutil.Process(pid)
                try: cmdline = proc.cmdline()
                except: cmdline = []
                cmd_str = " ".join([str(a).lower() for a in cmdline])
                if any(safe in cmd_str for safe in ['antigravity.exe', 'pyright', 'vscode', 'jedi', 'language_server', 'language-server', 'pylsp', 'edr.py', 'unquarantine.py']):
                    continue
                    
                for f in proc.open_files():
                    if f.path.endswith('.py') and 'lib\\' not in f.path.lower():
                        print(f"  [DEBUG-IDLE] Found malicious script in loud process: {f.path}")
                        if quarantine_dead_file(f.path):
                            proc.kill()
                            return True
                # If we couldn't find a script, quarantine the process binary if it's not a known interpreter
                if 'python' not in name:
                    quarantine_malware(proc)
                    # Don't blindly return True! If quarantine fails (e.g. system), we MUST continue searching!
            except: pass

    # 2. Heuristic 1: Behavioral Memory Scan (Temporal Correlation)
    suspicious_pids.sort(key=lambda x: x[5])

    for pid, name, cmdline, exe_path, cwd, age in suspicious_pids:
        print(f"[*] Analyzing suspicious process via behavioral memory: {name} PID: {pid} (Age: {age:.2f}s)")
        target_quarantine_paths = []
        
        # Better path resolution for interpreters
        if ('python' in name or 'python' in exe_path) and cmdline:
            for arg in cmdline[1:]:
                clean_arg = str(arg).strip('"').strip("'")
                if clean_arg.startswith('-'): continue
                
                # Try 1: As absolute path
                paths_to_check = [os.path.abspath(clean_arg)]
                # Try 2: Relative to process CWD
                if cwd:
                    paths_to_check.append(os.path.abspath(os.path.join(cwd, clean_arg)))
                # Try 3: As a filename in the CWD
                if cwd:
                    paths_to_check.append(os.path.join(cwd, clean_arg))
                
                found_script = False
                for p in paths_to_check:
                    # Case-insensitive path check for Windows
                    p_abs = os.path.abspath(p).lower()
                    if os.path.exists(p) and os.path.isfile(p):
                        # Ensure we don't quarantine whitelisted library scripts or OURSELVES
                        if p_abs == edr_script_path:
                            continue
                        
                        # Check content for indicators if it happens to be in a user directory
                        is_malicious = False
                        if not is_whitelisted(p_abs, os.path.basename(p_abs), whitelist, bypass_whitelist=True):
                            is_malicious = True
                        else:
                            # Second chance: If it's a python script in AppData, check content even if whitelisted
                            if 'appdata' in p_abs and p_abs.endswith('.py'):
                                try:
                                    with open(p, 'r', errors='ignore') as f:
                                        content = f.read(4000).lower()
                                        if any(ind in content for ind in ['fernet', 'encrypt', 'os.remove', 'cryptography']):
                                            print(f"  [DEBUG-DEEP] Found malicious indicators in whitelisted path: {p}")
                                            is_malicious = True
                                except: pass
                                
                        if is_malicious:
                            target_quarantine_paths.append(p)
                            found_script = True
                            print(f"  [DEBUG-PATH] Resolved script: {p}")
                            break
                if found_script: break
        
        elif exe_path and os.path.exists(exe_path):
            if not is_whitelisted(exe_path, name, whitelist):
                target_quarantine_paths.append(os.path.abspath(exe_path))
                print(f"  [DEBUG-PATH] Resolved executable: {exe_path}")
            
        for path in target_quarantine_paths:
            if quarantine_dead_file(path): return True

    # Heuristic 2: Any currently running process that has files open in TARGET_DIR - SLOW
    print("[*] Checking currently running processes for open file handles in target directory...")
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
        try:
            if proc.info['pid'] == my_pid:
                continue
                
            # Only check "recent" or "interpreter" processes to save time
            proc_age = current_time - proc.info.get('create_time', 0)
            name = proc.info.get('name', '').lower()
            if proc_age > 600.0 and 'python' not in name:
                continue

            open_files = proc.open_files()
            for file in open_files:
                if target_abs_path in file.path.lower():
                    exe_path = proc.info.get('exe') or ''
                    
                    # BYPASS WHITELIST: If a process has active handles in target dir during anomaly, it's fair game
                    if is_whitelisted(exe_path, proc.info.get('name', ''), whitelist, bypass_whitelist=True):
                        continue
                        
                    print(f"[*] Detected malicious process touching files! Name: {proc.info.get('name', 'Unknown')} PID: {proc.info['pid']}")
                    
                    # SPECIAL CASE: IDLE/Python script resolution via open files
                    if 'python' in name:
                        try: cmdline_a = proc.cmdline()
                        except: cmdline_a = []
                        cmd_str = " ".join([str(a).lower() for a in cmdline_a])
                        if any(safe in cmd_str for safe in ['antigravity.exe', 'pyright', 'vscode', 'jedi', 'language_server', 'language-server', 'pylsp']):
                            continue
                            
                        for f in open_files:
                            if f.path.endswith('.py') and 'lib\\' not in f.path.lower():
                                print(f"  [DEBUG-IDLE] Found script via open files: {f.path}")
                                if quarantine_dead_file(f.path):
                                    proc.kill()
                                    return True

                    quarantine_malware(proc)
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
                
    # Heuristic 4: Direct Deep Forensic Scan using Context Hint
    print("[*] Performing Deep Forensic Scan for malicious payloads...")
    search_paths = [
        os.path.abspath('.'), 
        os.path.abspath(TARGET_DIR),
        r"C:\Users\Dell\AppData\Local\Programs\Python\Python313\beast_mode\encrypt"
    ]
    
    # Add anomaly hint directory (where files were modified) and its parent
    if anomaly_hint_path:
        hint_dir = os.path.dirname(anomaly_hint_path)
        search_paths.append(os.path.abspath(hint_dir))
        search_paths.append(os.path.abspath(os.path.join(hint_dir, '..')))
        print(f"[*] Deep Forensic Hint: Active folder '{hint_dir}' added to search scope.")
    
    suspicious_files = []
    current_time = time.time()
    
    for base_path in search_paths:
        if not os.path.exists(base_path): continue
        for root, _, files in os.walk(base_path):
            if 'quarantined_data' in root.lower() or 'edr_backup' in root.lower(): continue
            for file in files:
                if file.endswith('.py') or file.endswith('.exe') or file.endswith('.pyw'):
                    full_path = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(full_path)
                        # Look for files modified since the anomaly window or very recently
                        if current_time - mtime < 45.0:
                            suspicious_files.append((full_path, mtime))
                    except: pass
    
    # Sort files by newest modification time
    suspicious_files.sort(key=lambda x: x[1], reverse=True)
    
    for path, mtime in suspicious_files:
        if not is_whitelisted(path, os.path.basename(path), whitelist):
            # Check if this script was modified recently OR if it's in the root during an anomaly
            print(f"[*] Deep Forensic fallback: Found suspect payload: {os.path.basename(path)}")
            if quarantine_dead_file(path):
                return True

    # Heuristic 5: Root Directory Cleanup (The "Last Resort")
    print("[*] Performing AGGRESSIVE Root Script Search (Last Resort)...")
    cwd_files = os.listdir(".")
    for file in cwd_files:
        if file.endswith(".py") and "edr" not in file.lower() and "unquarantine" not in file.lower():
            full_path = os.path.abspath(file)
            if not is_whitelisted(full_path, file, whitelist):
                # Search for forensic indicators in the script content
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        content = f.read().lower()
                        indicators = ["cryptography", "fernet", "encrypt", "os.rename", ".locked", "aes", "secret", "write_bytes"]
                        if any(x in content for x in indicators):
                            print(f"[!] AGGRESSIVE: Identified non-whitelisted ransomware script in root: {file}")
                            if quarantine_dead_file(full_path):
                                return True
                except: pass
                        
    print("[-] Could not automatically determine the malicious process.")
    return False

def analyze_loop(monitor, model):
    window_seconds = 2.0
    poll_interval = 0.01
    print("[*] EDR Real-Time ML Engine started...")
    
    while True:
        time.sleep(poll_interval)
        current_time = time.time()
        
        window_events = []
        with monitor.lock:
            while monitor.events_queue and (current_time - monitor.events_queue[0][1] > window_seconds):
                monitor.events_queue.popleft()
            window_events = list(monitor.events_queue)
        
        if len(window_events) < 4:
            continue
            
        counts = {'modified': 0, 'created': 0, 'deleted': 0, 'renamed': 0}
        entropies = []
        
        for event in window_events:
            ev_type, ev_time, ev_path = event
            counts[ev_type] += 1
            if ev_type in ['modified', 'created', 'renamed']:
                try:
                    entropy = calculate_entropy(ev_path)
                    if entropy > 0:
                        entropies.append(entropy)
                except:
                    pass
        
        avg_entropy = sum(entropies) / len(entropies) if entropies else 3.5
        
        mods_per_sec = counts['modified'] / window_seconds
        creates_per_sec = counts['created'] / window_seconds
        dels_per_sec = counts['deleted'] / window_seconds
        renames_per_sec = counts['renamed'] / window_seconds
        
        df = pd.DataFrame([{
            'modifications_per_sec': mods_per_sec,
            'creations_per_sec': creates_per_sec,
            'deletions_per_sec': dels_per_sec,
            'renames_per_sec': renames_per_sec,
            'entropy_avg': avg_entropy
        }])
        
        # -1 = Anomaly, 1 = Normal
        prediction = model.predict(df)[0]
        
        if prediction == -1:
            anomaly_start_time = window_events[0][1] if window_events else current_time - window_seconds
            anomaly_hint_dir = window_events[0][2] if window_events else None # Use the path of the modified file
            
            print(f"\n[!!!] ALERT: ANOMALOUS BEHAVIOR DETECTED (SUSPICIOUS ACTIVITY) [!!!]")
            print(f"Metrics -> Mods/s: {mods_per_sec:.1f}, Renames/s: {renames_per_sec:.1f}, Avg Entropy: {avg_entropy:.2f}")
            kill_ransomware_process(anomaly_window_start=anomaly_start_time, anomaly_hint_path=anomaly_hint_dir)
            restore_from_backup()
            print("[*] EDR System has mitigated the threat. Monitoring resuming...")
            time.sleep(1) # Prevent immediate re-trigger
            monitor.events_queue.clear()

def main():
    if not os.path.exists(TARGET_DIR):
        print(f"[-] Target directory {TARGET_DIR} not found. Run data_generator.py first.")
        return
        
    if not os.path.exists(MODEL_PATH):
        print("[-] Model not found! Run train_model.py first.")
        return

    model = joblib.load(MODEL_PATH)
    print(f"[*] Loaded Isolation Forest model from {MODEL_PATH}")

    create_shadow_copy()

    monitor = EDRMonitor()
    observer = Observer()
    observer.schedule(monitor, TARGET_DIR, recursive=True)
    observer.start()
    print(f"[+] Started monitoring directory: {TARGET_DIR}")

    memory_thread = threading.Thread(target=track_processes_loop, daemon=True)
    memory_thread.start()

    # Start analysis thread
    analysis_thread = threading.Thread(target=analyze_loop, args=(monitor, model), daemon=True)
    analysis_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
