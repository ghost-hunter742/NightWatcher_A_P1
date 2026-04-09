import os
import random
import string
import shutil

TARGET_DIR = "dummy_data"
NUM_FILES = 50

def generate_random_string(length=100):
    return ''.join(random.choices(string.ascii_letters + string.digits + " \n", k=length))

def create_dummy_data():
    if os.path.exists(TARGET_DIR):
        print(f"[!] Directory {TARGET_DIR} already exists. Recreating it...")
        shutil.rmtree(TARGET_DIR)
    
    os.makedirs(TARGET_DIR)
    print(f"[*] Creating {NUM_FILES} dummy files in {TARGET_DIR}...")
    
    for i in range(NUM_FILES):
        file_path = os.path.join(TARGET_DIR, f"important_file_{i}.txt")
        with open(file_path, "w") as f:
            # Generate random content
            content = generate_random_string(random.randint(500, 2000))
            f.write(content)

    print("[+] Dummy data generation complete!")

if __name__ == "__main__":
    create_dummy_data()
