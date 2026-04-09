
import edr
# I want to patch edr.py to print out the cache
import os, sys
def my_kill():
    import time
    print('MY KILL RANSOMWARE REACHED')
    for pid, data in list(edr.recent_processes_cache.items()):
        info = data.get('info')
        if not info: continue
        cmdline = info.get('cmdline') or []
        if any('ransomware' in str(c).lower() for c in cmdline):
            print(f'FOUND IN CACHE! data: {data}')
            c_time = time.time()
            f_seen = data.get('first_seen', 0)
            print(f'Age: {c_time - f_seen}')
    return False

edr.kill_ransomware_process = my_kill
edr.main()
