import argparse
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
import math
import os
import stat
import platform

# === Settings ===
SUSPICIOUS_EXTENSIONS = ['.locked', '.encrypted', '.payforunlock', '.enc']
COMPRESSED_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz']

if platform.system() == "Windows":
    WHITELISTED_PROCESSES = [
        'explorer.exe', 'System Idle Process', 'System', 'svchost.exe', 'csrss.exe',
        'wininit.exe', 'smss.exe', 'lsass.exe', 'services.exe', 'taskhostw.exe',
        'SearchIndexer.exe', 'OneDrive.exe', 'chrome.exe', 'python.exe', 'pythonw.exe'
    ]
    CRITICAL_PATHS = [
        "C:\\Windows\\System32",
        "C:\\Windows\\Registry",
        "C:\\Program Files",
        os.path.expandvars("%APPDATA%")
    ]
    DEFAULT_PATH = "C:\\TestFolder"
else:
    WHITELISTED_PROCESSES = ['launchd', 'WindowServer', 'kernel_task', 'loginwindow', 'python3', 'python3.12']
    CRITICAL_PATHS = [
        "/System/Library",
        "/Library",
        "/Applications",
        os.path.expanduser("~/Library")
    ]
    DEFAULT_PATH = os.path.expanduser("~/Desktop/security_project/testFolder")

CPU_USAGE_THRESHOLD = 50
SCORE_THRESHOLD = 100  # More strict
MASS_FILE_CREATE_THRESHOLD = 30
BIG_SCORE_FOR_MASS_WRITE = 5
MASS_FILE_DELETION_THRESHOLD = 30
BIG_SCORE_FOR_MASS_DELETION = 5
OUTBOUND_NETWORK_SPIKE = 50_000_000  # 50 MB

test_mode = False

# === Globals ===
process_scores = defaultdict(int)
process_file_create_counter = defaultdict(int)
process_deletion_counter = defaultdict(int)
process_net_usage = defaultdict(lambda: {'sent': 0, 'recv': 0})
last_mass_check_time = time.time()
deletion_check_time = time.time()

def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = -sum(p * math.log2(p) for p in (count / len(data) for count in byte_counts if count))
        return entropy
    except Exception:
        return 0.0

def log_alert(message):
    with open("alerts.log", "a") as log:
        log.write(f"{time.ctime()}: {message}\n")

def check_score_threshold(pid, name):
    if process_scores[pid] >= SCORE_THRESHOLD:
        msg = f"[!!!] ALERT: {name} (PID {pid}) flagged! Score = {process_scores[pid]}"
        print(msg)
        log_alert(msg)
        if not test_mode:
            try:
                psutil.Process(pid).kill()
            except Exception:
                pass

def check_critical_path_access(path, pid, name):
    if any(path.startswith(p) for p in CRITICAL_PATHS):
        print(f"[!!!] Unauthorized access to critical path: {path} by {name} (PID {pid})")
        process_scores[pid] += 5
        check_score_threshold(pid, name)

class FileEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        entropy = calculate_entropy(event.src_path)
        print(f"[*] Entropy of {event.src_path}: {entropy:.2f}")
        suspicious_ext = any(event.src_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        compressed_ext = any(event.src_path.lower().endswith(ext) for ext in COMPRESSED_EXTENSIONS)
        is_hidden = os.path.basename(event.src_path).startswith('.') if platform.system() != "Windows" else False

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                if name in WHITELISTED_PROCESSES:
                    continue
                process_file_create_counter[pid] += 1
                check_critical_path_access(event.src_path, pid, name)

                if is_hidden:
                    print(f"[!!!] Hidden file created by {name} (PID {pid})")
                    process_scores[pid] += 4
                if suspicious_ext:
                    print(f"[!!!] Suspicious file extension detected by {name} (PID {pid})")
                    process_scores[pid] += 4
                if entropy > 7.5:
                    if compressed_ext:
                        print(f"[!] High entropy compressed file by {name} (PID {pid})")
                        process_scores[pid] += 1
                    else:
                        print(f"[!!!] High entropy encrypted file by {name} (PID {pid})")
                        process_scores[pid] += 3

                check_score_threshold(pid, name)
                break
            except Exception:
                continue

        self.check_mass_file_creation()

    def on_deleted(self, event):
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] in WHITELISTED_PROCESSES:
                    continue
                pid = proc.info['pid']
                name = proc.info['name']
                process_deletion_counter[pid] += 1
                check_critical_path_access(event.src_path, pid, name)
                print(f"[!] File deleted by {name} (PID {pid})")
                check_score_threshold(pid, name)
                break
            except Exception:
                continue
        self.check_mass_deletions()

    def check_mass_file_creation(self):
        global last_mass_check_time
        for pid, count in process_file_create_counter.items():
            if count > MASS_FILE_CREATE_THRESHOLD:
                print(f"[!!!] Mass file creation: PID {pid} created {count} files!")
                process_scores[pid] += BIG_SCORE_FOR_MASS_WRITE
                check_score_threshold(pid, psutil.Process(pid).name())
        if time.time() - last_mass_check_time > 60:
            process_file_create_counter.clear()
            last_mass_check_time = time.time()

    def check_mass_deletions(self):
        global deletion_check_time
        for pid, count in process_deletion_counter.items():
            if count > MASS_FILE_DELETION_THRESHOLD:
                print(f"[!!!] Mass deletion: PID {pid} deleted {count} files!")
                process_scores[pid] += BIG_SCORE_FOR_MASS_DELETION
                check_score_threshold(pid, psutil.Process(pid).name())
        if time.time() - deletion_check_time > 60:
            process_deletion_counter.clear()
            deletion_check_time = time.time()

def check_high_cpu_usage():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in WHITELISTED_PROCESSES:
                continue
            cpu = proc.cpu_percent(interval=0.1)
            if cpu > CPU_USAGE_THRESHOLD + 20:
                process_scores[proc.pid] += 4
            elif cpu > CPU_USAGE_THRESHOLD + 10:
                process_scores[proc.pid] += 3
            elif cpu > CPU_USAGE_THRESHOLD:
                process_scores[proc.pid] += 2
        except Exception:
            continue

def monitor_network_usage():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in WHITELISTED_PROCESSES:
                continue
            io = proc.io_counters()
            if hasattr(io, 'other') and io.other > OUTBOUND_NETWORK_SPIKE:
                print(f"[!!!] High outbound traffic from {proc.info['name']} (PID {proc.pid})")
                process_scores[proc.pid] += 8
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def show_top_suspects():
    top = sorted(process_scores.items(), key=lambda x: x[1], reverse=True)[:5]
    print("\n[Live Dashboard] Top Suspicious Processes:")
    for pid, score in top:
        try:
            name = psutil.Process(pid).name()
            print(f"  PID: {pid} | Name: {name} | Score: {score}")
        except Exception:
            continue
    print("-" * 40)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-mode", action="store_true", help="Run in simulation mode without killing processes.")
    args = parser.parse_args()
    test_mode = args.test_mode

    os.makedirs(DEFAULT_PATH, exist_ok=True)
    event_handler = FileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=DEFAULT_PATH, recursive=True)
    observer.start()

    print("[*] Behavioral Monitor Started. Test mode =", test_mode)
    try:
        while True:
            check_high_cpu_usage()
            monitor_network_usage()
            show_top_suspects()
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
