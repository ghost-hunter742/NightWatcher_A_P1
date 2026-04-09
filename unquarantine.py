import os
import json
import shutil

QUARANTINE_DIR = "quarantined_data"
MAPPING_FILE = "quarantine_original_path.json"

def unquarantine_file():
    print("[*] EDR Unquarantine Utility Started")
    
    if not os.path.exists(MAPPING_FILE):
        print("[-] No quarantine mapping file found. Nothing to restore.")
        return
        
    try:
        with open(MAPPING_FILE, "r") as f:
            mapping = json.load(f)
    except Exception as e:
        print(f"[-] Failed to read mapping file: {e}")
        return
        
    if not mapping:
        print("[*] Quarantine is empty.")
        return
        
    print("\n[!] The following files are currently in quarantine:\n")
    
    items = list(mapping.items())
    for idx, (q_path, orig_path) in enumerate(items):
        file_name = os.path.basename(q_path)
        print(f"  [{idx}] {file_name}")
        print(f"      Original Path: {orig_path}")
        print(f"      Quarantine Path: {q_path}\n")
        
    while True:
        choice = input("[?] Enter the index of the file to unquarantine (or 'q' to quit): ").strip()
        if choice.lower() == 'q':
            print("[*] Exiting.")
            return
            
        try:
            choice_idx = int(choice)
            if 0 <= choice_idx < len(items):
                break
            else:
                print("[-] Invalid index. Please try again.")
        except ValueError:
            print("[-] Please enter a valid number.")

    q_path, orig_path = items[choice_idx]
    
    if not os.path.exists(q_path):
        print(f"[-] Error: Quarantined file missing at {q_path}!")
        
        # Give option to just remove the dead entry
        if input("[?] Remove missing entry from registry? (y/n): ").lower() == 'y':
            del mapping[q_path]
            with open(MAPPING_FILE, "w") as f:
                json.dump(mapping, f, indent=4)
            print("[+] Dead entry removed.")
        return

    # Ensure the original directory still exists
    orig_dir = os.path.dirname(orig_path)
    if not os.path.exists(orig_dir):
        try:
            os.makedirs(orig_dir)
        except Exception as e:
            print(f"[-] Failed to recreate original directory: {e}")
            return
            
    print(f"\n[*] Restoring {os.path.basename(q_path)}...")
    try:
        shutil.move(q_path, orig_path)
        print(f"[+] Successfully restored to: {orig_path}")
        
        # Remove from mapping
        del mapping[q_path]
        with open(MAPPING_FILE, "w") as f:
            json.dump(mapping, f, indent=4)
            
        print("[+] Quarantine registry updated.")
    except Exception as e:
        print(f"[-] Failed to restore file: {e}")

if __name__ == "__main__":
    unquarantine_file()
