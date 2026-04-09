
import edr, threading, time, psutil
def dump_cache():
    while True:
        time.sleep(1)
        print(f'CACHE DUMP SIZE: {len(edr.recent_processes_cache)}')
        for p, d in list(edr.recent_processes_cache.items()):
            if 'info' in d and d['info'] and d['info'].get('cmdline'):
                cmd = d['info']['cmdline']
                if any('ransomware' in str(c).lower() for c in cmd):
                     print(f'FOUND IN CACHE TICK: {p} -> {d}')
t = threading.Thread(target=dump_cache, daemon=True)
t.start()
edr.main()
