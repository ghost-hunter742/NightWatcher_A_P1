import os
import json
import shutil

def main():
    print("[!] INITIATING MANUAL RESTORATION PROCESS...")
    
    if not os.path.exists("original_path.json"):
        print("[-] Error: 'original_path.json' not found! Cannot locate backup mapping.")
        print("[-] Ensure you are running this script in the root directory where the EDR was running.")
        return
        
    try:
        with open("original_path.json", "r") as f:
            path_mapping = json.load(f)
            
        success_count = 0
        fail_count = 0
            
        for backup_path, original_path in path_mapping.items():
            if os.path.exists(backup_path):
                # Ensure the restored file does NOT have the .locked extension
                restored_path = original_path
                if restored_path.endswith('.locked'):
                    restored_path = restored_path[:-7]
                
                # Clean up: If the ransomware left a .locked file in the destination, remove it
                malicious_locked_file = restored_path + '.locked'
                if os.path.exists(malicious_locked_file):
                    try:
                        os.remove(malicious_locked_file)
                    except:
                        pass
                        
                # Ensure the original directory exists before copying
                os.makedirs(os.path.dirname(restored_path), exist_ok=True)
                
                shutil.copy2(backup_path, restored_path)
                print(f"[+] Restored: {restored_path}")
                success_count += 1
            else:
                print(f"[-] Missing backup file: {backup_path}")
                fail_count += 1
                
        print(f"\n[*] Restoration complete. Successfully restored {success_count} files.")
        if fail_count > 0:
            print(f"[-] Failed to restore {fail_count} files (missing backups).")
            
    except Exception as e:
        print(f"[-] An error occurred during restoration: {e}")

if __name__ == "__main__":
    main()
